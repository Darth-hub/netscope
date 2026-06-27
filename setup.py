from setuptools import setup, find_packages

setup(
    name="netscope",
    version="1.0.0",
    description="Network packet analyzer and host security scanner",
    author="Ayush Ranjan",
    author_email="ayushranjan112400@gmail.com",
    url="https://github.com/Darth-hub/netscope",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "netscope=netscope.cli:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
