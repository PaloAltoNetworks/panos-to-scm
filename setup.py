from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Assuming you have a README.md file
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="panos-to-scm",
    version="1.0.0",
    author="Eric Chickering",
    author_email="echickerin@paloaltonetworks.omc",
    description="Migrate PanOS XML Config to Strata Cloud Manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/echickering/panos-to-scm",
    packages=find_packages(),
    install_requires=[
        "certifi==2022.6.15",
        "cffi==1.15.1",
        "charset-normalizer==2.1.1",
        "cryptography==37.0.4",
        "idna==3.3",
        "oauthlib==3.2.0",
        "pycparser==2.21",
        "PyJWT==2.4.0",
        "PyYAML==6.0",
        "requests==2.28.1",
        "requests-oauthlib==1.3.1",
        "urllib3==1.26.12",
    ],
    classifiers=[
        # Choose appropriate classifiers
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)