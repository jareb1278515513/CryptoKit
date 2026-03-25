"""CLI adapters."""

from __future__ import annotations

import argparse
import json

from cryptokit.interfaces.api import (
	api_base64_decode,
	api_base64_encode,
	api_hash_text,
	api_hmac_text,
	api_pbkdf2,
	api_symmetric_decrypt,
	api_symmetric_encrypt,
	api_utf8_decode,
	api_utf8_encode,
)


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(prog="cryptokit", description="CryptoKit CLI")
	subparsers = parser.add_subparsers(dest="command", required=True)

	b64_encode_parser = subparsers.add_parser("base64-encode")
	b64_encode_parser.add_argument("--text", required=True)

	b64_decode_parser = subparsers.add_parser("base64-decode")
	b64_decode_parser.add_argument("--payload", required=True)

	utf8_encode_parser = subparsers.add_parser("utf8-encode")
	utf8_encode_parser.add_argument("--text", required=True)
	utf8_encode_parser.add_argument("--output", default="hex", choices=["raw", "hex", "base64"])

	utf8_decode_parser = subparsers.add_parser("utf8-decode")
	utf8_decode_parser.add_argument("--payload", required=True)
	utf8_decode_parser.add_argument("--encoding", default="hex", choices=["hex", "base64"])

	hash_parser = subparsers.add_parser("hash")
	hash_parser.add_argument("--text", required=True)
	hash_parser.add_argument("--algorithm", default="sha256")
	hash_parser.add_argument("--output", default="hex", choices=["raw", "hex", "base64"])

	hmac_parser = subparsers.add_parser("hmac")
	hmac_parser.add_argument("--text", required=True)
	hmac_parser.add_argument("--key", required=True)
	hmac_parser.add_argument("--algorithm", default="sha256")
	hmac_parser.add_argument("--output", default="hex", choices=["raw", "hex", "base64"])

	pbkdf2_parser = subparsers.add_parser("pbkdf2")
	pbkdf2_parser.add_argument("--password", required=True)
	pbkdf2_parser.add_argument("--salt", required=True)
	pbkdf2_parser.add_argument("--iterations", type=int, default=100000)
	pbkdf2_parser.add_argument("--dklen", type=int, default=32)
	pbkdf2_parser.add_argument("--algorithm", default="sha256")
	pbkdf2_parser.add_argument("--output", default="hex", choices=["raw", "hex", "base64"])

	sym_encrypt_parser = subparsers.add_parser("symmetric-encrypt")
	sym_encrypt_parser.add_argument("--algorithm", required=True, choices=["aes", "sm4", "rc6"])
	sym_encrypt_parser.add_argument("--mode", default="ecb", choices=["ecb", "cbc", "ctr"])
	sym_encrypt_parser.add_argument("--payload", required=True)
	sym_encrypt_parser.add_argument("--key-hex", required=True)
	sym_encrypt_parser.add_argument("--iv-hex")
	sym_encrypt_parser.add_argument("--input-encoding", default="utf8", choices=["utf8", "hex", "base64"])
	sym_encrypt_parser.add_argument("--output", default="hex", choices=["hex", "base64"])

	sym_decrypt_parser = subparsers.add_parser("symmetric-decrypt")
	sym_decrypt_parser.add_argument("--algorithm", required=True, choices=["aes", "sm4", "rc6"])
	sym_decrypt_parser.add_argument("--mode", default="ecb", choices=["ecb", "cbc", "ctr"])
	sym_decrypt_parser.add_argument("--payload", required=True)
	sym_decrypt_parser.add_argument("--key-hex", required=True)
	sym_decrypt_parser.add_argument("--iv-hex")
	sym_decrypt_parser.add_argument("--input-encoding", default="hex", choices=["hex", "base64"])
	sym_decrypt_parser.add_argument("--output", default="utf8", choices=["utf8", "hex", "base64"])

	return parser


def run_cli(argv: list[str] | None = None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)

	if args.command == "base64-encode":
		result = api_base64_encode(args.text)
	elif args.command == "base64-decode":
		result = api_base64_decode(args.payload)
	elif args.command == "utf8-encode":
		result = api_utf8_encode(args.text, output=args.output)
	elif args.command == "utf8-decode":
		result = api_utf8_decode(args.payload, encoding=args.encoding)
	elif args.command == "hash":
		result = api_hash_text(args.text, algorithm=args.algorithm, output=args.output)
	elif args.command == "hmac":
		result = api_hmac_text(
			args.text,
			key=args.key,
			algorithm=args.algorithm,
			output=args.output,
		)
	elif args.command == "symmetric-encrypt":
		result = api_symmetric_encrypt(
			args.payload,
			algorithm=args.algorithm,
			mode=args.mode,
			key_hex=args.key_hex,
			iv_hex=args.iv_hex,
			input_encoding=args.input_encoding,
			output=args.output,
		)
	elif args.command == "symmetric-decrypt":
		result = api_symmetric_decrypt(
			args.payload,
			algorithm=args.algorithm,
			mode=args.mode,
			key_hex=args.key_hex,
			iv_hex=args.iv_hex,
			input_encoding=args.input_encoding,
			output=args.output,
		)
	else:
		result = api_pbkdf2(
			args.password,
			salt=args.salt,
			iterations=args.iterations,
			dklen=args.dklen,
			algorithm=args.algorithm,
			output=args.output,
		)

	print(json.dumps(result.to_dict(), ensure_ascii=False))
	return 0 if result.ok else 1


__all__ = ["build_parser", "run_cli"]
