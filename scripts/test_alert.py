import requests

BASE_URL = "http://127.0.0.1:5000"


def test_backend():

    response = requests.get(
        BASE_URL + "/",
        timeout=10
    )

    print("Backend:", response.status_code)

    print(response.json())


def test_dashboard():

    response = requests.get(
        BASE_URL + "/api/dashboard/summary",
        timeout=10
    )

    print("Dashboard:", response.status_code)

    print(response.json())


def test_alerts():

    response = requests.get(
        BASE_URL + "/api/alerts/",
        timeout=10
    )

    print("Alerts:", response.status_code)

    print(response.json())


if __name__ == "__main__":

    test_backend()

    test_dashboard()

    test_alerts()