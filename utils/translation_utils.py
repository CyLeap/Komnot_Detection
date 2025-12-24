from deep_translator import GoogleTranslator


def translate_to_khmer(text):
    """
    Translates the given text to Khmer using Google Translate.
    """
    try:
        translator = GoogleTranslator(source='auto', target='km')
        translated = translator.translate(text)
        return translated
    except Exception as e:
        print(f"Translation error: {e}")
        return text  # Return original text if translation fails


# Example usage
if __name__ == "__main__":
    original_text = "Welcome to our application"
    khmer_translation = translate_to_khmer(original_text)
    print(f"English: {original_text}")
    print(f"Khmer: {khmer_translation}")
