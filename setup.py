import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sdvalidator",
    version="2.1.14",
    author="Calum Baird",
    author_email="calum.baird7011@gmail.com",
    description="SPF and DMARC validation tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/calumsbaird/sdvalidator",
    packages=setuptools.find_packages(),
    entry_points = {
        'console_scripts': ['sdvalidate=sdvalidator.command_line:sdvalidate'],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
