<div align="center">
<img src="static/logo.svg">
<h1>Vidzy</h1>
A free and open source alternative to TikTok

<a href="https://vidzy.codeberg.page/">Website</a>
&nbsp;•&nbsp;
<a href="https://matrix.to/#/#vidzysocial:fedora.im">Matrix</a>

<br>

![License: AGPL-v3.0](https://img.shields.io/github/license/vidzy-social/vidzy?style=for-the-badge)
[![GitHub contributors](https://img.shields.io/github/contributors-anon/vidzy-social/vidzy?style=for-the-badge)](#contributors)

</div>

<br>

## Install

    git clone https://github.com/vidzy-social/vidzy
    cd vidzy
    pip install -r requirements.txt
    cp .env.sample .env
    # Use your preferred editor to configure .env (ex. 'nano .env')
    python -m waitress --port=8080 --call app:create_app

## Screenshots

### Homepage

![Homepage Screenshot](./screenshots/homepage.png)

### Admin Panel

![Admin Panel Screenshot](./screenshots/admin_panel.png)

## Features

We have very ALPHA federation through [ActivityPub](https://www.w3.org/TR/activitypub/).

## Contributing

Thank you for considering contributing to Vidzy! To contribute, fork the repo and add your contribution. Then, send a pull request and if it is helpful we will gladly accept it.

## Security Vulnerabilities

If you discover a security vulnerability within Vidzy, please send an e-mail to me via [vidzy_social@proton.me](mailto:vidzy_social@proton.me). All security vulnerabilities will be promptly addressed.

## License

Vidzy is open-source software licensed under the GNU Affero General Public License v3.0

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ProgramminCat"><img src="https://avatars.githubusercontent.com/u/72707293?v=4?s=100" width="100px;" alt="ProgramminCat"/><br /><sub><b>ProgramminCat</b></sub></a><br /><a href="#code-ProgramminCat" title="Code">💻</a> <a href="#design-ProgramminCat" title="Design">🎨</a> <a href="#ideas-ProgramminCat" title="Ideas, Planning, & Feedback">🤔</a> <a href="#question-ProgramminCat" title="Answering Questions">💬</a> <a href="#maintenance-ProgramminCat" title="Maintenance">🚧</a> <a href="#review-ProgramminCat" title="Reviewed Pull Requests">👀</a> <a href="#security-ProgramminCat" title="Security">🛡️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/kodxana"><img src="https://avatars.githubusercontent.com/u/16674412?v=4?s=100" width="100px;" alt="Madiator2011"/><br /><sub><b>Madiator2011</b></sub></a><br /><a href="#design-kodxana" title="Design">🎨</a> <a href="#code-kodxana" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/nycterent"><img src="https://avatars.githubusercontent.com/u/81133?v=4?s=100" width="100px;" alt="Marty"/><br /><sub><b>Marty</b></sub></a><br /><a href="#code-nycterent" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://chuso.net"><img src="https://avatars.githubusercontent.com/u/3270352?v=4?s=100" width="100px;" alt="Chuso Pérez"/><br /><sub><b>Chuso Pérez</b></sub></a><br /><a href="#security-chusopr" title="Security">🛡️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
