import os

def test_dns():
    response = os.popen('nslookup www.exemplo.com 172.17.8.9').read()
    print(response)

if __name__ == "__main__":
    test_dns()
