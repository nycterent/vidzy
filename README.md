<div align="center">
<img src="static/logo.png">
<h1>Vidzy</h1>
A free and open source alternative to TikTok

<a href="https://vidzy.codeberg.page/">Website</a>
&nbsp;•&nbsp;
<a href="https://matrix.to/#/#vidzysocial:fedora.im">Matrix</a>

![License: AGPL-v3.0](./license_badge.svg)
</div>

<br><br>

## Install

	git clone https://codeberg.org/vidzy/vidzy
	cd vidzy
	pip install -r requirements.txt
	python -m waitress --port=8080 --call app:create_app

## Screenshots

### Homepage
![Homepage Screenshot](./screenshots/homepage.png)

## Features

The project is in very early stages, and we will update the repo as soon as the code is available and tested. We will later add federation through [ActivityPub](https://www.w3.org/TR/activitypub/).

## Contributing

Thank you for considering contributing to Vidzy! To contribute, fork the repo and add your contribution. Then, send a pull request and if it is helpful we will gladly accept it.

## Security Vulnerabilities

If you discover a security vulnerability within Vidzy, please send an e-mail to me via [vidzy_social@proton.me](mailto:vidzy_social@proton.me). All security vulnerabilities will be promptly addressed.

## License

Vidzy is open-sourced software licensed under the AGPL license.