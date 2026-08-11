import cv2

def decode_qr(image_path):
    image = cv2.imread(image_path)

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)

    if data:
        return [data]
    else:
        return []

if __name__ == "__main__":
    image_path = input("Enter QR image path: ")
    decoded_data = decode_qr(image_path)

    if decoded_data:
        print("\n--- QR Decoded Data ---")
        for d in decoded_data:
            print(d)
    else:
        print("\nNo QR code detected.")
