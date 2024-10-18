#!/usr/bin/env python

from dotenv import load_dotenv

load_dotenv()

import asyncio
from dcap_attestation.api import main


if __name__ == '__main__':
    asyncio.run(main())
