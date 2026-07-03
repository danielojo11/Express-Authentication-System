import qrcode from "qrcode";

export const generateQRCode = (issuer, accountLabel, secret) => {
  const otpauthUrl = `otpauth://totp/${encodeURIComponent(
    issuer,
  )}:${encodeURIComponent(accountLabel)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;

  return qrcode.toDataURL(otpauthUrl);
};
