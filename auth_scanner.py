import urllib.parse
import requests

def analyze_url(url):
    print(f"Analyzing URL: {url}")
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    print("\nParameters found:")
    for key, value in params.items():
        print(f"  {key}: {value}")

    # Check for redirect_uri
    if 'redirect_uri' in params:
        redirect_uri = params['redirect_uri'][0]
        print(f"\n[+] Found redirect_uri: {redirect_uri}")
        
        # Fuzzing payloads for Open Redirect
        payloads = [
            "https://evil.com",
            "//evil.com",
            "https://authenticate.riotgames.com.evil.com",
            "https://google.com"
        ]

        print("\n[+] Testing for Open Redirect vulnerabilities...")
        base_url = url.split("?")[0]
        
        for payload in payloads:
            # Construct new query parameters
            new_params = params.copy()
            new_params['redirect_uri'] = [payload]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = f"{base_url}?{new_query}"
            
            try:
                response = requests.get(test_url, allow_redirects=False)
                print(f"  Testing payload: {payload}")
                print(f"    Status Code: {response.status_code}")
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    print(f"    Location Header: {location}")
                    if "evil.com" in location or "google.com" in location:
                        print("    [!!!] POTENTIAL OPEN REDIRECT DETECTED")
                else:
                    print("    No redirect detected.")
            except Exception as e:
                print(f"    Error testing payload: {e}")

    else:
        print("\n[-] No redirect_uri parameter found to test.")

if __name__ == "__main__":
    target_url = "https://authenticate.riotgames.com/?client_id=prod-xsso-leagueoflegends&code_challenge=GZSVkBl_3KCkYXR7bfhBM_dxCaPhNTJsU2C1nGHBDsI&locale=en_US&method=riot_identity&platform=web&redirect_uri=https%3A%2F%2Fauth.riotgames.com%2Fauthorize%3Fclient_id%3Dprod-xsso-leagueoflegends%26code_challenge%3DGZSVkBl_3KCkYXR7bfhBM_dxCaPhNTJsU2C1nGHBDsI%26code_challenge_method%3DS256%26prompt%3Dsignup%26redirect_uri%3Dhttps%3A%2F%2Fxsso.leagueoflegends.com%2Fredirect%26response_type%3Dcode%26scope%3Dopenid%2520account%2520email%2520offline_access%26state%3Dd0ee81509008ed057fc9997235%26uri%3Dhttps%3A%2F%2Fsignup.leagueoflegends.com%2Fen-gb%2Fsignup%2Fredownload"
    analyze_url(target_url)
