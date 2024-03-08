import requests

BASE_URL = "https://api.github.com/repos/apache/logging-log4j2/issues?per_page=100&page="
BASE_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

def main():
    page_number = 0

    while(page_number == 0 or len(page) != 0):
        page_number += 1
        url = BASE_URL + str(page_number)
        response = requests.get(url, headers=BASE_HEADERS)
        page = response.json()
        if (len(page) != 0):
            process_page(page)

def process_page(page):
    data_length = len(page)

    for i in range(0, data_length):
        process_data(page[i])

def process_data(data):
    print(data["title"])

if __name__ == "__main__":
    main()