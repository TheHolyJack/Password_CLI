from setuptools import setup, find_packages

setup(
    name="password-checker",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "password-checker=password_checker.cli:main",
        ],
    },
)