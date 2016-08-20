from setuptools import setup, find_packages

setup(
    name='gpp',
    version='1.0.0.',
    author='Darryl lane',
    author_email='DarrylLane101@gmail.com',
    url='https://github.com/darryllane/gpp',
    packages=['gpp'],
    license='LICENSE.txt',
    description='''
    Find and decrypt all cpass entries in SYSVOL. Relates to MS14-025''',
    long_description=open('README.md').read(),
    install_requires=[
        "docopt",
        "lxml",
    ],
)

