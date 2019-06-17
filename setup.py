from setuptools import setup, find_packages


with open("README.md") as f:
    readme = f.read()

with open("LICENSE") as f:
    license = f.read()

setup(
    name="torwxpay",
    version="0.0.1",
    description="async wxpay for tornado",
    long_description=readme,
    author="jay lau",
    author_email="cappyclear@gmail.com",
    url="",
    license=license,
    packages=find_packages(exclude=("tests", "docs")),
)
