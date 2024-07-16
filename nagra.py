import argparse
import base64
import json
import sys

from pywidevine import PSSH
from pywidevine.license_protocol_pb2 import WidevinePsshData


class NagraPSSH:
    NAGRA_SYSTEMID = bytes.fromhex("adb41c242dbf4a6d958b4457c0d27b95")

    def __init__(
            self,
            pssh: str | bytes
    ):
        """
        Parse a Nagra PSSH from either a PSSH Box or Base64 Nagra data.
        Author: github.com/DevLARLEY
        """
        if isinstance(pssh, str):
            pssh = base64.b64decode(pssh)

        if pssh[0] != 123:
            if pssh[12:28] != self.NAGRA_SYSTEMID:
                raise Exception("Not a Nagra PSSH")
            nagra_data = base64.b64decode(pssh[32:])
        else:
            nagra_data = pssh

        self._nagra = json.loads(nagra_data)

    def to_widevine(self):
        return PSSH.new(
            system_id=PSSH.SystemId.Widevine,
            init_data=WidevinePsshData(
                # I know that this is deprecated, but Nagra still uses the Algorithm field.
                algorithm=WidevinePsshData.Algorithm.AESCTR,
                key_ids=[bytes.fromhex(self._nagra.get('keyId').replace('-', ''))],
                content_id=self._nagra.get('contentId').encode()
            ).SerializeToString()
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--nagra", action="store")
    args = parser.parse_args()

    if not args.nagra:
        parser.print_help()
        exit(-1)

    nagra = NagraPSSH(args.nagra)
    print(nagra.to_widevine())
