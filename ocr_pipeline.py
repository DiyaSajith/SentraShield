import easyocr
import re

# Initialize the reader once to avoid reloading model on every call
# This will download the model on the first run if not present
reader = easyocr.Reader(['en'], gpu=False) 

def extract_text_from_image(image_path):
    try:
        # detail=0 returns only the text content
        result = reader.readtext(image_path, detail=0)
        return " ".join(result)
    except Exception as e:
        print(f"Error extracting text: {e}")
        return ""

def extract_urls(text):
    if not text:
        return []
    # Improved regex to capture more URL formats
    url_pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|net|org|io|gov|edu|co|us|uk|info|biz|site|online|store|tech|website|space|fun)[^\s]*)"
    
    matches = re.findall(url_pattern, text)
    # Clean up matches
    cleaned_urls = []
    for match in matches:
        match = re.sub(r'[.,;!?)]+$', '', match)
        if match:
            cleaned_urls.append(match)
            
    return list(set(cleaned_urls))

if __name__ == "__main__":
    image_path = input("Enter screenshot path: ")
    text = extract_text_from_image(image_path)

    print("\n--- Extracted Text ---")
    print(text)

    urls = extract_urls(text)
    print("\n--- URLs Found ---")
    print(urls)
