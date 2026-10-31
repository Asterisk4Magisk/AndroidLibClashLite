// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package libclash;

public final class Traffic {
  private long upload, download;

  public Traffic() {}

  public Traffic(long upload, long download) {
    this.upload = upload;
    this.download = download;
  }

  public long getUpload() {
    return upload;
  }

  public void setUpload(long value) {
    upload = value;
  }

  public long getDownload() {
    return download;
  }

  public void setDownload(long value) {
    download = value;
  }

  @Override
  public boolean equals(Object value) {
    return value instanceof Traffic
        && ((Traffic) value).upload == upload
        && ((Traffic) value).download == download;
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(upload, download);
  }

  @Override
  public String toString() {
    return "Traffic{Upload:" + upload + ",Download:" + download + "}";
  }
}
