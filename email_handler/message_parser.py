# email_handler/message_parser.py
import json

def parse_encrypted_message(email_body):
    """Extracts the JSON block from the email body."""
    try:
        start_marker = "---BEGIN ENCRYPTED MESSAGE---"
        end_marker = "---END ENCRYPTED MESSAGE---"
        
        start_index = email_body.find(start_marker)
        end_index = email_body.find(end_marker)
        
        if start_index == -1 or end_index == -1:
            return None
            
        json_str = email_body[start_index + len(start_marker):end_index].strip()
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return None