package com.phishlab.hash;

public record ScanResult(String fileName, String hash, boolean isMalicious, String message) {
}
