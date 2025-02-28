from __future__ import annotations

from pathlib import Path

import click
from joserfc.errors import DecodeError

from ._config import Config
from ._vault import Algorithms
from ._vault import decrypt
from ._vault import encrypt


@click.group()
@click.option("-k", "--key", type=str, help="A key to encrypt the content.")
@click.option("--algorithm", type=str, help="The algorithm to use.")
@click.pass_context
def cli(ctx: click.Context, key: str | None = None, algorithm: Algorithms | None = None):
    config = Config()
    if key:
        config.raw_key = key
    if algorithm:
        config.algorithm = algorithm
    ctx.obj = config


@cli.command()
@click.argument("filename", type=click.Path())
@click.pass_obj
def create(config: Config, filename: str):
    file_path = Path(filename)
    if file_path.exists():
        click.echo(f'File "{file_path}" already exists.', err=True)
        raise click.Abort()

    if config.raw_key is None:
        config.raw_key = click.prompt("Enter a key", type=str, hide_input=True)

    value = encrypt("", config.key, config.algorithm, config.encryption)
    file_path.write_text(value)


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.pass_obj
def edit(config: Config, filename: str):
    if config.raw_key is None:
        config.raw_key = click.prompt("Enter a key", type=str, hide_input=True)

    file_path = Path(filename)
    content = file_path.read_bytes()
    try:
        value = decrypt(content, config.key)
    except DecodeError as err:
        click.echo("Incorrect key", err=True)
        raise click.Abort() from err

    message = click.edit(value)
    value = encrypt(message, config.key, config.algorithm, config.encryption)
    file_path.write_text(value)


@cli.command()
@click.argument("filename", type=click.Path(exists=True))
@click.pass_obj
def view(config: Config, filename: str):
    if config.raw_key is None:
        config.raw_key = click.prompt("Enter a key", type=str, hide_input=True)

    file_path = Path(filename)
    try:
        content = decrypt(file_path.read_bytes(), config.key)
    except DecodeError as err:
        click.echo("Incorrect key", err=True)
        raise click.Abort() from err

    click.echo("-----------------")
    click.echo(content)
    click.echo("-----------------")
