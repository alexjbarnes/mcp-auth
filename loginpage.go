package mcpauth

import "html/template"

// LoginData holds the template data passed to the login page. When
// providing a custom LoginTemplate via Config, your template receives
// this struct. All hidden form fields must be included for the OAuth
// flow to work correctly.
type LoginData struct {
	CSRFToken           string
	ClientID            string
	ClientName          string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Resource            string
	Error               string
	Title               string
	Subtitle            string
}

var loginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f5f5f5;
    color: #1a1a1a;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }
  .card h1 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
  }
  .card p.sub {
    font-size: 0.85rem;
    color: #666;
    margin-bottom: 1.5rem;
  }
  .consent {
    background: #f8f9fa;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .consent p { margin-bottom: 0.3rem; }
  .consent p:last-child { margin-bottom: 0; }
  .consent .redirect { color: #666; word-break: break-all; }
  .consent code { font-size: 0.8rem; }
  .error {
    background: #fef2f2;
    color: #991b1b;
    border: 1px solid #fecaca;
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  label {
    display: block;
    font-size: 0.85rem;
    font-weight: 500;
    margin-bottom: 0.35rem;
    color: #333;
  }
  input[type="text"], input[type="password"] {
    width: 100%;
    padding: 0.55rem 0.7rem;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
    font-size: 0.9rem;
    outline: none;
    transition: border-color 0.15s;
    margin-bottom: 1rem;
  }
  input[type="text"]:focus, input[type="password"]:focus {
    border-color: #2563eb;
    box-shadow: 0 0 0 2px rgba(37,99,235,0.15);
  }
  button {
    width: 100%;
    padding: 0.6rem;
    background: #1a1a1a;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
  }
  button:hover { background: #333; }
  button:active { background: #000; }
</style>
</head>
<body>
<div class="card">
  <h1>{{.Title}}</h1>
  <p class="sub">{{.Subtitle}}</p>
  <div class="consent">
    <p><strong>{{if .ClientName}}{{.ClientName}}{{else}}{{.ClientID}}{{end}}</strong> is requesting access.</p>
    {{if .RedirectURI}}<p class="redirect">You will be redirected to: <code>{{.RedirectURI}}</code></p>{{end}}
  </div>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="POST">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <input type="hidden" name="scope" value="{{.Scope}}">
    <input type="hidden" name="resource" value="{{.Resource}}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>`))
