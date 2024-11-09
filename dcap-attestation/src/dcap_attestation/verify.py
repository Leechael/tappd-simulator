import os
import subprocess
import tempfile

def verify_quote_with_collateral(bin: bytes, dcap_qvl_path: str = "dcap-qvl") -> bool:
    try:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
            temp_path = temp_file.name
            temp_file.write(bin)
        try:
            result = subprocess.run(
                [dcap_qvl_path, "verify", temp_path],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    except FileNotFoundError:
        raise FileNotFoundError(f"dcap-qvl is not found: {dcap_qvl_path}")
    except Exception as e:
        raise Exception(f"Unknown error: {str(e)}")
