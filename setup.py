from setuptools import setup

version = open("VERSION", "rb").read().strip().decode("ascii")

setup(
    name="pygost",
    version=version,
    description="Pure Python GOST cryptographic functions library",
    long_description=open("README", "rb").read().decode("utf-8"),
    author="Sergey Matveev",
    author_email="stargrave@stargrave.org",
    url="http://pygost.cypherpunks.ru/",
    license="GPLv3",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=["pygost", "pygost.asn1schemas"],
    package_data={
        "pygost": ["stubs/**/*.pyi"],
    },
    data_files=(
        ('', (
            "AUTHORS",
            "COPYING",
            "INSTALL",
            "NEWS",
            "README",
            "THANKS",
            "VERSION",
        )),
    ),
    tests_require=["pyderasn~=4.4"],
)
