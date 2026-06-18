from setuptools import setup, find_namespace_packages
setup(
    name="netsekhmet-xiv",
    version="14.0.0",
    packages=find_namespace_packages(include=['netsekhmet', 'netsekhmet.*']),
    entry_points={"console_scripts": ["netsekhmet=netsekhmet.cli:main"]},
    install_requires=["httpx","impacket","flask","sqlalchemy","colorama","cryptography","requests","paramiko","aiohttp","rich","dnspython","pyOpenSSL","psutil","pynput","pypsrp","pyscreenshot","pyfiglet","flask-socketio","eventlet","netifaces","typer","pyreadline3"]
)
