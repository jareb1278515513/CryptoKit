"""命令行接口适配层。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptokit.interfaces.api import (
	api_base64_decode,
	api_base64_encode,
	api_hash_text,
	api_hmac_text,
	api_pbkdf2,
	api_ecc_generate_keypair,
	api_ecdsa_sign_sha1,
	api_ecdsa_verify_sha1,
	api_rsa_decrypt,
	api_rsa_encrypt,
	api_rsa_generate_keypair,
	api_rsa_sign_sha1,
	api_rsa_verify_sha1,
	api_symmetric_decrypt,
	api_symmetric_encrypt,
	api_utf8_decode,
	api_utf8_encode,
)


def _load_text_arg(inline_value: str | None, file_path: str | None, arg_name: str) -> str:
	"""优先读取内联参数，否则从文件读取文本参数。

	Args:
		inline_value: 命令行内联参数值。
		file_path: 文件路径参数。
		arg_name: 参数名，用于错误提示。

	Returns:
		str: 读取到的文本内容。

	Raises:
		ValueError: 内联值和文件路径均缺失时抛出。
	"""
	if inline_value:
		return inline_value
	if file_path:
		return Path(file_path).read_text(encoding="utf-8")
	raise ValueError(f"参数 {arg_name} 不能为空")


def build_parser() -> argparse.ArgumentParser:
	"""构建 CryptoKit CLI 参数解析器。"""
	parser = argparse.ArgumentParser(prog="cryptokit", description="CryptoKit 命令行工具")
	parser.add_argument("--trace", action="store_true", help="显示算法执行中间过程")
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

	rsa_gen_parser = subparsers.add_parser("rsa-generate")
	rsa_gen_parser.add_argument("--bits", type=int, default=1024)

	rsa_encrypt_parser = subparsers.add_parser("rsa-encrypt")
	rsa_encrypt_parser.add_argument("--payload", required=True)
	rsa_encrypt_parser.add_argument("--public-key-pem")
	rsa_encrypt_parser.add_argument("--public-key-file")
	rsa_encrypt_parser.add_argument("--input-encoding", default="utf8", choices=["utf8", "hex", "base64"])
	rsa_encrypt_parser.add_argument("--output", default="base64", choices=["hex", "base64"])

	rsa_decrypt_parser = subparsers.add_parser("rsa-decrypt")
	rsa_decrypt_parser.add_argument("--payload", required=True)
	rsa_decrypt_parser.add_argument("--private-key-pem")
	rsa_decrypt_parser.add_argument("--private-key-file")
	rsa_decrypt_parser.add_argument("--input-encoding", default="base64", choices=["hex", "base64"])
	rsa_decrypt_parser.add_argument("--output", default="utf8", choices=["utf8", "hex", "base64"])

	rsa_sign_parser = subparsers.add_parser("rsa-sign")
	rsa_sign_parser.add_argument("--payload", required=True)
	rsa_sign_parser.add_argument("--private-key-pem")
	rsa_sign_parser.add_argument("--private-key-file")
	rsa_sign_parser.add_argument("--input-encoding", default="utf8", choices=["utf8", "hex", "base64"])
	rsa_sign_parser.add_argument("--output", default="base64", choices=["hex", "base64"])

	rsa_verify_parser = subparsers.add_parser("rsa-verify")
	rsa_verify_parser.add_argument("--payload", required=True)
	rsa_verify_parser.add_argument("--signature", required=True)
	rsa_verify_parser.add_argument("--public-key-pem")
	rsa_verify_parser.add_argument("--public-key-file")
	rsa_verify_parser.add_argument("--input-encoding", default="utf8", choices=["utf8", "hex", "base64"])
	rsa_verify_parser.add_argument("--signature-encoding", default="base64", choices=["hex", "base64"])

	ecc_gen_parser = subparsers.add_parser("ecc-generate")
	ecc_gen_parser.add_argument("--curve", default="nist-p160", choices=["nist-p160"])

	ecdsa_sign_parser = subparsers.add_parser("ecdsa-sign")
	ecdsa_sign_parser.add_argument("--payload", required=True)
	ecdsa_sign_parser.add_argument("--private-key-pem")
	ecdsa_sign_parser.add_argument("--private-key-file")
	ecdsa_sign_parser.add_argument("--input-encoding", default="utf8", choices=["utf8", "hex", "base64"])
	ecdsa_sign_parser.add_argument("--output", default="base64", choices=["hex", "base64"])

	ecdsa_verify_parser = subparsers.add_parser("ecdsa-verify")
	ecdsa_verify_parser.add_argument("--payload", required=True)
	ecdsa_verify_parser.add_argument("--signature", required=True)
	ecdsa_verify_parser.add_argument("--public-key-pem")
	ecdsa_verify_parser.add_argument("--public-key-file")
	ecdsa_verify_parser.add_argument("--input-encoding", default="utf8", choices=["utf8", "hex", "base64"])
	ecdsa_verify_parser.add_argument("--signature-encoding", default="base64", choices=["hex", "base64"])

	return parser


def run_cli(argv: list[str] | None = None) -> int:
	"""执行 CLI 命令并输出 JSON 结果。

	Args:
		argv: 可选命令参数列表；为空时读取系统参数。

	Returns:
		int: 进程退出码，成功为 0，失败为 1。
	"""
	parser = build_parser()
	args = parser.parse_args(argv)

	if args.command == "base64-encode":
		result = api_base64_encode(args.text, trace=args.trace)
	elif args.command == "base64-decode":
		result = api_base64_decode(args.payload, trace=args.trace)
	elif args.command == "utf8-encode":
		result = api_utf8_encode(args.text, output=args.output, trace=args.trace)
	elif args.command == "utf8-decode":
		result = api_utf8_decode(args.payload, encoding=args.encoding, trace=args.trace)
	elif args.command == "hash":
		result = api_hash_text(args.text, algorithm=args.algorithm, output=args.output, trace=args.trace)
	elif args.command == "hmac":
		result = api_hmac_text(
			args.text,
			key=args.key,
			algorithm=args.algorithm,
			output=args.output,
			trace=args.trace,
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
			trace=args.trace,
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
			trace=args.trace,
		)
	elif args.command == "rsa-generate":
		result = api_rsa_generate_keypair(bits=args.bits, trace=args.trace)
	elif args.command == "rsa-encrypt":
		try:
			public_key_pem = _load_text_arg(args.public_key_pem, args.public_key_file, "public_key")
			result = api_rsa_encrypt(
				args.payload,
				public_key_pem=public_key_pem,
				input_encoding=args.input_encoding,
				output=args.output,
				trace=args.trace,
			)
		except ValueError as exc:
			from cryptokit.shared.errors import StatusCode
			from cryptokit.shared.result import OperationResult

			result = OperationResult.failure(StatusCode.INVALID_INPUT, str(exc))
	elif args.command == "rsa-decrypt":
		try:
			private_key_pem = _load_text_arg(args.private_key_pem, args.private_key_file, "private_key")
			result = api_rsa_decrypt(
				args.payload,
				private_key_pem=private_key_pem,
				input_encoding=args.input_encoding,
				output=args.output,
				trace=args.trace,
			)
		except ValueError as exc:
			from cryptokit.shared.errors import StatusCode
			from cryptokit.shared.result import OperationResult

			result = OperationResult.failure(StatusCode.INVALID_INPUT, str(exc))
	elif args.command == "rsa-sign":
		try:
			private_key_pem = _load_text_arg(args.private_key_pem, args.private_key_file, "private_key")
			result = api_rsa_sign_sha1(
				args.payload,
				private_key_pem=private_key_pem,
				input_encoding=args.input_encoding,
				output=args.output,
				trace=args.trace,
			)
		except ValueError as exc:
			from cryptokit.shared.errors import StatusCode
			from cryptokit.shared.result import OperationResult

			result = OperationResult.failure(StatusCode.INVALID_INPUT, str(exc))
	elif args.command == "rsa-verify":
		try:
			public_key_pem = _load_text_arg(args.public_key_pem, args.public_key_file, "public_key")
			result = api_rsa_verify_sha1(
				args.payload,
				signature=args.signature,
				public_key_pem=public_key_pem,
				input_encoding=args.input_encoding,
				signature_encoding=args.signature_encoding,
				trace=args.trace,
			)
		except ValueError as exc:
			from cryptokit.shared.errors import StatusCode
			from cryptokit.shared.result import OperationResult

			result = OperationResult.failure(StatusCode.INVALID_INPUT, str(exc))
	elif args.command == "ecc-generate":
		result = api_ecc_generate_keypair(trace=args.trace)
	elif args.command == "ecdsa-sign":
		try:
			private_key_pem = _load_text_arg(args.private_key_pem, args.private_key_file, "private_key")
			result = api_ecdsa_sign_sha1(
				args.payload,
				private_key_pem=private_key_pem,
				input_encoding=args.input_encoding,
				output=args.output,
				trace=args.trace,
			)
		except ValueError as exc:
			from cryptokit.shared.errors import StatusCode
			from cryptokit.shared.result import OperationResult

			result = OperationResult.failure(StatusCode.INVALID_INPUT, str(exc))
	elif args.command == "ecdsa-verify":
		try:
			public_key_pem = _load_text_arg(args.public_key_pem, args.public_key_file, "public_key")
			result = api_ecdsa_verify_sha1(
				args.payload,
				signature=args.signature,
				public_key_pem=public_key_pem,
				input_encoding=args.input_encoding,
				signature_encoding=args.signature_encoding,
				trace=args.trace,
			)
		except ValueError as exc:
			from cryptokit.shared.errors import StatusCode
			from cryptokit.shared.result import OperationResult

			result = OperationResult.failure(StatusCode.INVALID_INPUT, str(exc))
	else:
		result = api_pbkdf2(
			args.password,
			salt=args.salt,
			iterations=args.iterations,
			dklen=args.dklen,
			algorithm=args.algorithm,
			output=args.output,
			trace=args.trace,
		)

	print(json.dumps(result.to_dict(), ensure_ascii=False))
	return 0 if result.ok else 1


__all__ = ["build_parser", "run_cli"]
