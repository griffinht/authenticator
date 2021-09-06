package net.stzups.authenticator.totp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;

import java.awt.image.BufferedImage;

public class QrCode {
    public static BufferedImage getQrCode(String uri) throws WriterException {
        return MatrixToImageWriter.toBufferedImage(new QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 0, 0));
    }
}
