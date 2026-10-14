# extractor.py
import email
from email import policy
import sys

with open(sys.argv[1], 'rb') as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

for part in msg.walk():
    if part.get_content_type() in ["text/plain", "text/html"]:
        print(f"\n--- Contenido: {part.get_content_type()} ---")
        print(part.get_content())