package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/yaml.v2"
)

var (
	configFilePath = fmt.Sprintf("%s/.aws/roles", os.Getenv("HOME"))
	roleArnRe      = regexp.MustCompile(`^arn:aws:iam::(.+):role/([^/]+)(/.+)?$`)
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <role> [<command> <args...>]\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	flag.Usage = usage
}

func defaultFormat() string {
	var shell = os.Getenv("SHELL")

	switch runtime.GOOS {
	case "windows":
		if os.Getenv("SHELL") == "" {
			return "powershell"
		}
		fallthrough
	default:
		if strings.HasSuffix(shell, "fish") {
			return "fish"
		}
		return "bash"
	}
}

func main() {
	var (
		duration = flag.Duration("duration", time.Hour, "The duration that the credentials will be valid for.")
		format   = flag.String("format", defaultFormat(), "Format can be 'bash' or 'powershell'.")
		console  = flag.Bool("console", false, "Generate a console signin URL using temporary credentials.")
	)
	flag.Parse()
	argv := flag.Args()
	if len(argv) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	stscreds.DefaultDuration = *duration

	role := argv[0]
	args := argv[1:]

	// Load credentials from configFilePath if it exists, else use regular AWS config
	var creds *credentials.Value
	var err error
	if roleArnRe.MatchString(role) {
		creds, err = assumeRole(role, "", *duration)
	} else if _, err = os.Stat(configFilePath); err == nil {
		fmt.Fprintf(os.Stderr, "WARNING: using deprecated role file (%s), switch to config file"+
			" (https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html)\n",
			configFilePath)
		config, err := loadConfig()
		must(err)

		roleConfig, ok := config[role]
		if !ok {
			must(fmt.Errorf("%s not in %s", role, configFilePath))
		}

		creds, err = assumeRole(roleConfig.Role, roleConfig.MFA, *duration)
	} else {
		creds, err = assumeProfile(role)
	}

	must(err)

	if *console {
		signInTokenURL := generateSigninTokenURL(creds)
		signInToken, err := requestSigninToken(signInTokenURL)
		consoleURL := generateConsoleURL(signInToken, *duration)

		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				// Errors are already on Stderr.
				os.Exit(1)
			}

			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("%s\n", consoleURL)
		return
	}

	if len(args) == 0 {
		switch *format {
		case "powershell":
			printPowerShellCredentials(role, creds)
		case "bash":
			printCredentials(role, creds)
		case "fish":
			printFishCredentials(role, creds)
		default:
			flag.Usage()
			os.Exit(1)
		}
		return
	}

	err = execWithCredentials(role, args, creds)
	must(err)
}

func execWithCredentials(role string, argv []string, creds *credentials.Value) error {
	argv0, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}

	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
	os.Setenv("ASSUMED_ROLE", role)

	env := os.Environ()
	return syscall.Exec(argv0, argv, env)
}

// printCredentials prints the credentials in a way that can easily be sourced
// with bash.
func printCredentials(role string, creds *credentials.Value) {
	fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("export AWS_SECURITY_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("export ASSUMED_ROLE=\"%s\"\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# eval $(%s)\n", strings.Join(os.Args, " "))
}

// printFishCredentials prints the credentials in a way that can easily be sourced
// with fish.
func printFishCredentials(role string, creds *credentials.Value) {
	fmt.Printf("set -gx AWS_ACCESS_KEY_ID \"%s\";\n", creds.AccessKeyID)
	fmt.Printf("set -gx AWS_SECRET_ACCESS_KEY \"%s\";\n", creds.SecretAccessKey)
	fmt.Printf("set -gx AWS_SESSION_TOKEN \"%s\";\n", creds.SessionToken)
	fmt.Printf("set -gx AWS_SECURITY_TOKEN \"%s\";\n", creds.SessionToken)
	fmt.Printf("set -gx ASSUMED_ROLE \"%s\";\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# eval (%s)\n", strings.Join(os.Args, " "))
}

// printPowerShellCredentials prints the credentials in a way that can easily be sourced
// with Windows powershell using Invoke-Expression.
func printPowerShellCredentials(role string, creds *credentials.Value) {
	fmt.Printf("$env:AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("$env:AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("$env:AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("$env:AWS_SECURITY_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("$env:ASSUMED_ROLE=\"%s\"\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# %s | Invoke-Expression \n", strings.Join(os.Args, " "))
}

// assumeProfile assumes the named profile which must exist in ~/.aws/config
// (https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) and returns the temporary STS
// credentials.
func assumeProfile(profile string) (*credentials.Value, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile:                 profile,
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: getTokenCode,
	}))

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, err
	}
	return &creds, nil
}

// assumeRole assumes the given role and returns the temporary STS credentials.
func assumeRole(role, mfa string, duration time.Duration) (*credentials.Value, error) {
	sess := session.Must(session.NewSession())

	svc := sts.New(sess)

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(role),
		RoleSessionName: aws.String("cli"),
		DurationSeconds: aws.Int64(int64(duration / time.Second)),
	}

	if mfa != "" {
		params.SerialNumber = aws.String(mfa)
		token, err := getTokenCode()
		if err != nil {
			return nil, err
		}
		params.TokenCode = aws.String(token)
	}

	resp, err := svc.AssumeRole(params)

	if err != nil {
		return nil, err
	}

	var creds credentials.Value
	creds.AccessKeyID = *resp.Credentials.AccessKeyId
	creds.SecretAccessKey = *resp.Credentials.SecretAccessKey
	creds.SessionToken = *resp.Credentials.SessionToken

	return &creds, nil
}

type roleConfig struct {
	Role string `yaml:"role"`
	MFA  string `yaml:"mfa"`
}

type config map[string]roleConfig

func getTokenCode() (string, error) {
	if token := os.Getenv("AWS_MFA_TOKEN"); token != "" {
		return token, nil
	}

	if zenity := os.Getenv("AWS_MFA_ZENITY"); zenity == "true" {
		token, err := readTokenCodeZenity()
		if err != nil {
			log.Fatal("Unable to get MFA token code using Zenity:", err)
		}
		return token, nil
	}

	token, err := readTokenCode()

	return token, err
}

// readTokenCodeZenity read the MFA code using a Zenity GUI entry dialogue
func readTokenCodeZenity() (token string, err error) {
	zenityPath, err := exec.LookPath("zenity")
	if err != nil {
		log.Fatal("Unable to find zenity in PATH. Is it installed?")
	}

	cmd := exec.Cmd{
		Path: zenityPath,
		Args: []string{zenityPath, "--entry", "--text=MFA Code"},
	}

	log.Print(cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("Unable to get stdout pipe for Zenity:", err)
	}

	err = cmd.Start()
	if err != nil {
		log.Fatal("Zenity failed:", err)
	}

	stdoutContents := make([]byte, 7)
	if _, err = stdout.Read(stdoutContents); err != nil {
		log.Fatal("Unable to read stdout pipe for Zenity:", err)
	}

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}

	token = strings.TrimSpace(string(stdoutContents))

	return token, nil
}

// readTokenCode reads the MFA token from Stdin.
func readTokenCode() (string, error) {
	r := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "MFA code: ")
	text, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

// loadConfig loads the ~/.aws/roles file.
func loadConfig() (config, error) {
	raw, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	roleConfig := make(config)
	return roleConfig, yaml.Unmarshal(raw, &roleConfig)
}

func must(err error) {
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Errors are already on Stderr.
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type getSigninTokenRequestParams struct {
	SessionID    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
}

func generateSigninTokenURL(credentials *credentials.Value) string {
	reqParamsStruct := getSigninTokenRequestParams{
		SessionID:    credentials.AccessKeyID,
		SessionKey:   credentials.SecretAccessKey,
		SessionToken: credentials.SessionToken,
	}

	requestParamsString, err := json.Marshal(reqParamsStruct)

	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Errors are already on Stderr.
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	escapedRequestString := url.QueryEscape(string(requestParamsString))
	url := "https://signin.aws.amazon.com/federation?Action=getSigninToken&Session=" + escapedRequestString

	return url
}

type requestSigninTokenResponse struct {
	SignInToken string `json:"SigninToken"`
}

func requestSigninToken(signinTokenURL string) (string, error) {
	var signinTokenResp requestSigninTokenResponse
	resp, err := http.Get(signinTokenURL)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	if err := json.Unmarshal(body, &signinTokenResp); err != nil {
		return "", err
	}

	return signinTokenResp.SignInToken, nil
}

func generateConsoleURL(signinToken string, duration time.Duration) string {
	consoleURL := "https://signin.aws.amazon.com/federation?Action=login&Issuer=&SigninToken=" + signinToken + "&SessionDuration=" + string(duration/time.Second)
	region := os.Getenv("AWS_DEFAULT_REGION")
	consoleURL = consoleURL + "&Destination=" + url.QueryEscape("https://"+region+".console.aws.amazon.com/")
	return consoleURL
}

type CustomCredentialsProvider stuct{}
func (m *CustomCredentialsProvider) Retrieve() (Value, error) {
	// Create session in source profile
	// Get session token with MFA
	// Cache Result
	// Assume role in other accounts
}
func (m *CustomCredentialsProvider) IsExpired() bool {}
