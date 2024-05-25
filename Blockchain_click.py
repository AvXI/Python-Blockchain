import click
from flask import Flask, jsonify, request
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from bip32 import BIP32, HARDENED_INDEX
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from sqlalchemy.exc import IntegrityError

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
db = SQLAlchemy(app)

# Example elliptic curve for post-quantum cryptography
curve = Curve.get_curve('secp256k1')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(64), nullable=False)
    recipient = db.Column(db.String(64), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    signature = db.Column(db.String(256), nullable=False)

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(64), unique=True, nullable=False)
    key_secret = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, nullable=False)
    transaction_history = db.relationship('Transaction', backref='wallet', lazy=True)

    def create_key(self):
        random_seed = os.urandom(32)
        master_key = BIP32.from_seed(random_seed)
        key = master_key.derive(HARDENED_INDEX)
        return key

    def generate_address(self):
        return self.create_key().address()

    def get_balance(self):
        return self.balance

    def create_transaction(self, recipient, amount):
        if self.balance < amount:
            raise ValueError("Insufficient funds")
        transaction = Transaction(sender=self.address, recipient=recipient, amount=amount, timestamp=time.time(), signature='')
        transaction.signature = self.sign_transaction(transaction)
        return transaction

    def sign_transaction(self, transaction):
        private_key = ECPrivateKey.from_secret(bytes.fromhex(self.key_secret))
        signature = private_key.sign(json.dumps(transaction.to_dict(), default=str, sort_keys=True).encode())
        return signature

# Create database tables
db.create_all()

@click.group()
def cli():
    pass

@cli.command()
def create_wallet():
    """Create a new wallet."""
    wallet = Wallet()
    wallet.key_secret = wallet.create_key().secret.hex()
    wallet.address = wallet.generate_address()

    try:
        db.session.add(wallet)
        db.session.commit()
        click.echo(f"Wallet created successfully. Address: {wallet.address}, Balance: {wallet.get_balance()}")
    except IntegrityError:
        db.session.rollback()
        click.echo("Address already exists. Wallet creation failed.")
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command()
@click.argument('address')
def get_wallet(address):
    """Get wallet information."""
    wallet = Wallet.query.filter_by(address=address).first()
    if not wallet:
        click.echo("Wallet not found.")
        return

    click.echo(f"Address: {wallet.address}, Balance: {wallet.get_balance()}")

@cli.command()
@click.option('--sender', prompt='Sender Address', help='Sender address')
@click.option('--recipient', prompt='Recipient Address', help='Recipient address')
@click.option('--amount', prompt='Amount', type=float, help='Transaction amount')
def new_transaction(sender, recipient, amount):
    """Create a new transaction."""
    sender_wallet = Wallet.query.filter_by(address=sender).first()
    recipient_wallet = Wallet.query.filter_by(address=recipient).first()

    if not sender_wallet or not recipient_wallet:
        click.echo("Invalid sender or recipient address.")
        return

    try:
        transaction = sender_wallet.create_transaction(recipient, amount)
        recipient_wallet.balance += amount
        sender_wallet.balance -= amount
        db.session.add(transaction)
        db.session.commit()
        click.echo("Transaction created and added to pending transactions.")
    except ValueError as e:
        click.echo(f"Error: {str(e)}")
    except Exception as e:
        db.session.rollback()
        click.echo(f"Error: {str(e)}")

@cli.command()
@click.option('--miner', prompt='Miner Address', help='Miner address')
def mine(miner):
    """Mine pending transactions."""
    miner_wallet = Wallet.query.filter_by(address=miner).first()

    if not miner_wallet:
        click.echo("Invalid miner address.")
        return

    try:
        reward = 10  # Reward for mining a block
        miner_wallet.balance += reward
        db.session.commit()
        click.echo(f"Block mined successfully. Reward: {reward}, Balance: {miner_wallet.get_balance()}")
    except ValueError as e:
        click.echo(f"Error: {str(e)}")
    except Exception as e:
        db.session.rollback()
        click.echo(f"Error: {str(e)}")

if __name__ == "__main__":
    cli()
