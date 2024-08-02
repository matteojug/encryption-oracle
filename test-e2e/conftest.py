def pytest_addoption(parser):
    parser.addoption("--url", action="store", default="http://localhost:3000")
