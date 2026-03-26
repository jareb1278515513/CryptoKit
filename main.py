"""CryptoKit 命令行入口模块。"""

from cryptokit.interfaces.cli import run_cli


def main() -> int:
    """启动 CLI 并返回进程退出码。

    Returns:
        int: 命令执行完成后的退出码。
    """
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
