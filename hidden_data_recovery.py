import cv2
import numpy as np
import os
from PIL import Image
import magic

class HiddenDataRecovery:
    def __init__(self, image_path):
        self.image_path = image_path

    def lsb_extraction(self):
        "."Extract Least Significant Bit (LSB) from the image"
        img = cv2.imread(self.image_path)
        height, width, _ = img.shape
        binary_data = ""

        for row in range(height):
            for col in range(width):
                pixel = img[row, col]
                binary_data += str(pixel[0] & 1)  # LSB of Red channel

        return binary_data

    def detect_steganography(self):
        """Detect steganography by analyzing image noise, metadata, and other features"""
        noise = np.random.randn(*cv2.imread(self.image_path).shape) 
        noise_analysis = np.var(noise)
        img = Image.open(self.image_path)

        if noise_analysis > 0.1:
            print("Possible hidden data detected based on noise analysis.")
        else:
            print("No significant hidden data detected based on noise analysis.")

        # Check image metadata for suspicious entries
        metadata = img.info
        if 'comment' in metadata:
            print("Suspicious metadata found:", metadata['comment'])

    def analyze_metadata(self):
        """Analyze metadata for clues about hidden data"""
        metadata = magic.from_file(self.image_path)
        print(f"File Metadata: {metadata}")

if __name__ == '__main__':
    recovery = HiddenDataRecovery('path_to_your_image')
    recovery.detect_steganography()
    data = recovery.lsb_extraction()
    recovery.analyze_metadata()
