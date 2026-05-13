"""
IIDS Voice Alert Module
Arabic TTS alerts for blocked IPs during CSV analysis.
Uses gTTS for text-to-speech and pygame for audio playback.
All playback runs in daemon threads to avoid freezing Streamlit.
"""
import threading
import tempfile
import time
import os

# ── Arabic number words mapping ──
_ONES = {
    0: "صفر", 1: "واحد", 2: "اثنان", 3: "ثلاثة", 4: "أربعة",
    5: "خمسة", 6: "ستة", 7: "سبعة", 8: "ثمانية", 9: "تسعة",
    10: "عشرة", 11: "أحد عشر", 12: "اثنا عشر", 13: "ثلاثة عشر",
    14: "أربعة عشر", 15: "خمسة عشر", 16: "ستة عشر", 17: "سبعة عشر",
    18: "ثمانية عشر", 19: "تسعة عشر",
}

_TENS = {
    2: "عشرون", 3: "ثلاثون", 4: "أربعون", 5: "خمسون",
    6: "ستون", 7: "سبعون", 8: "ثمانون", 9: "تسعون",
}

_HUNDREDS = {
    1: "مئة", 2: "مئتان", 3: "ثلاثمئة", 4: "أربعمئة", 5: "خمسمئة",
    6: "ستمئة", 7: "سبعمئة", 8: "ثمانمئة", 9: "تسعمئة",
}


def _number_to_arabic(n: int) -> str:
    """Convert an integer (0-255) to Arabic words."""
    if n < 0 or n > 255:
        return str(n)
    if n <= 19:
        return _ONES[n]
    if n < 100:
        tens, ones = divmod(n, 10)
        if ones == 0:
            return _TENS[tens]
        return f"{_ONES[ones]} و{_TENS[tens]}"
    # 100-255
    hundreds, remainder = divmod(n, 100)
    h_word = _HUNDREDS[hundreds]
    if remainder == 0:
        return h_word
    return f"{h_word} و{_number_to_arabic(remainder)}"


def _ip_to_arabic(ip: str) -> str:
    """Convert an IP address like '172.16.0.5' to Arabic words with 'نقطة' separators."""
    parts = ip.split(".")
    arabic_parts = []
    for part in parts:
        try:
            arabic_parts.append(_number_to_arabic(int(part)))
        except ValueError:
            arabic_parts.append(part)
    return " نقطة ".join(arabic_parts)


# ── Attack type → Arabic sentence mapping ──
_ATTACK_MESSAGES = {
    "DoS":             "تحذير أمني. تم اكتشاف هجوم حجب خدمة من عنوان {ip}. تم حظر العنوان تلقائياً.",
    "Brute Force":     "تحذير أمني. تم اكتشاف محاولة اختراق متكررة من عنوان {ip}. تم حظر العنوان تلقائياً.",
    "Port Scan":       "تحذير أمني. تم اكتشاف مسح منافذ مشبوه من عنوان {ip}. تم حظر العنوان تلقائياً.",
    "Reconnaissance":  "تحذير أمني. تم اكتشاف هجوم استطلاع من عنوان {ip}. تم حظر العنوان تلقائياً.",
}

_DEFAULT_MESSAGE = "تحذير أمني. تم اكتشاف هجوم مشبوه من عنوان {ip}. تم حظر العنوان تلقائياً."


def build_message(attack_type: str, ip: str) -> str:
    """Build the Arabic alert sentence for the given attack type and IP."""
    arabic_ip = _ip_to_arabic(ip)
    template = _ATTACK_MESSAGES.get(attack_type, _DEFAULT_MESSAGE)
    return template.format(ip=arabic_ip)


def speak(text: str):
    """Convert text to speech using gTTS, play with pygame in a daemon thread, clean up."""
    def _speak_thread():
        tmp_path = None
        try:
            from gtts import gTTS
            import pygame

            # Generate TTS mp3 to a temp file
            tts = gTTS(text=text, lang="ar", slow=False)
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".mp3")
            os.close(tmp_fd)
            tts.save(tmp_path)

            # Add 0.3s silence before speaking for natural feel
            time.sleep(0.3)

            # Play with pygame
            pygame.mixer.init()
            pygame.mixer.music.load(tmp_path)
            pygame.mixer.music.play()

            # Wait for playback to finish
            while pygame.mixer.music.get_busy():
                time.sleep(0.1)

            pygame.mixer.music.unload()
            pygame.mixer.quit()

        except Exception as e:
            print(f"[IIDS Voice Alert] Error: {e}")
        finally:
            # Clean up temp file
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    t = threading.Thread(target=_speak_thread, daemon=True)
    t.start()


def voice_alert(attack_type: str, ip: str):
    """Main entry point: build Arabic message and speak it in background."""
    message = build_message(attack_type, ip)
    speak(message)
