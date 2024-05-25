from flask import Flask, request, jsonify
import json
import hashlib
import time
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from bip32 import BIP32, HARDENED_INDEX
from flask_sqlalchemy import SQLAlchemy
import requests
import os
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

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

@app.route('/wallet', methods=['POST'])
def create_wallet():
    wallet = Wallet()
    wallet.key_secret = wallet.create_key().secret.hex()
    wallet.address = wallet.generate_address()

    try:
        db.session.add(wallet)
        db.session.commit()
        response = {
            'address': wallet.address,
            'balance': wallet.get_balance(),
        }
        return jsonify(response), 201
    except IntegrityError:
        db.session.rollback()
        return 'Address already exists', 400
    except Exception as e:
        return str(e), 500

@app.route('/wallet/<address>', methods=['GET'])
def get_wallet(address):
    wallet = Wallet.query.filter_by(address=address).first()
    if not wallet:
        return 'Wallet not found', 404

    response = {
        'address': wallet.address,
        'balance': wallet.get_balance(),
    }
    return jsonify(response), 200

@app.route('/transaction', methods=['POST'])
def new_transaction():
    data = request.get_json()
    required_fields = ['sender_address', 'recipient_address', 'amount']
    if not all(field in data for field in required_fields):
        return 'Invalid transaction data', 400

    sender_address = data['sender_address']
    recipient_address = data['recipient_address']
    amount = data['amount']

    sender_wallet = Wallet.query.filter_by(address=sender_address).first()
    recipient_wallet = Wallet.query.filter_by(address=recipient_address).first()

    if not sender_wallet or not recipient_wallet:
        return 'Invalid sender or recipient address', 400

    try:
        transaction = sender_wallet.create_transaction(recipient_address, amount)
        recipient_wallet.balance += amount
        sender_wallet.balance -= amount
        db.session.add(transaction)
        db.session.commit()
        response = {'message': 'Transaction created and added to pending transactions'}
        return jsonify(response), 201
    except ValueError as e:
        return str(e), 400
    except Exception as e:
        db.session.rollback()
        return str(e), 500

@app.route('/mine', methods=['POST'])
def mine():
    data = request.get_json()
    required_fields = ['miner_address']
    if not all(field in data for field in required_fields):
        return 'Invalid miner data', 400

    miner_address = data['miner_address']
    miner_wallet = Wallet.query.filter_by(address=miner_address).first()

    if not miner_wallet:
        return 'Invalid miner address', 400

    try:
        reward = 10  # Reward for mining a block
        miner_wallet.balance += reward
        db.session.commit()
        response = {'message': 'Block mined successfully', 'reward': reward, 'balance': miner_wallet.get_balance()}
        return jsonify(response), 200
    except ValueError as e:
        return str(e), 400
    except Exception as e:
        db.session.rollback()
        return str(e), 500

@app.route('/chain', methods=['GET'])
def get_chain():
    transactions = Transaction.query.all()
    response = {'transactions': [tx.to_dict() for tx in transactions]}
    return jsonify(response), 200

if __name__ == "__main__":
    app.run(port=5000, ssl_context='adhoc')
