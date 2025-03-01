from __future__ import annotations

from pathlib import Path
from typing import cast

import click
from joserfc.errors import DecodeError
from joserfc.jwk import OctKey

from ._config import UserConfig
from ._vault import AlgorithmTypes
from ._vault import decrypt
from ._vault import encrypt


@click.group()
@click.option("-k", "--key", type=str, help="A key to encrypt the content.")
@click.option("--algorithm", type=str, help="The algorithm to use.")
@click.pass_context
def cli(ctx: click.Context, key: str | None = None, algorithm: AlgorithmTypes | None = None):
    config = UserConfig.create()
    if key:
        config.raw_key = key
    if algorithm:
        config.algorithm = algorithm
    ctx.obj = config


@cli.command()
@click.argument("filename", type=click.Path())
@click.pass_obj
def create(config: UserConfig, filename: str):
    file_path = Path(filename)
    if file_path.exists():
        click.echo(f'File "{file_path}" already exists.', err=True)
        raise click.Abort()

    if config.raw_key is None:
        config.raw_key = click.prompt("Enter a key", type=str, hide_input=True)

    key = cast(OctKey, config.key)
    value = encrypt("", key, config.algorithm, config.encryption)
    file_path.write_text(value)


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.pass_obj
def edit(config: UserConfig, filename: str):
    if config.raw_key is None:
        config.raw_key = click.prompt("Enter a key", type=str, hide_input=True)

    key = cast(OctKey, config.key)
    file_path = Path(filename)
    content = file_path.read_bytes()
    try:
        value = decrypt(content, key)
    except DecodeError as err:
        click.echo("Incorrect key", err=True)
        raise click.Abort() from err

    message = click.edit(value)
    if message is None:
        return

    text = encrypt(message, key, config.algorithm, config.encryption)
    file_path.write_text(text)


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.pass_obj
def view(config: UserConfig, filename: str):
    if config.raw_key is None:
        config.raw_key = click.prompt("Enter a key", type=str, hide_input=True)

    key = cast(OctKey, config.key)
    file_path = Path(filename)
    try:
        content = decrypt(file_path.read_bytes(), key)
    except DecodeError as err:
        click.echo("Incorrect key", err=True)
        raise click.Abort() from err

    click.echo("\n-----------------")
    click.echo(content)
    click.echo("-----------------")
