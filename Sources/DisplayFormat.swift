import Foundation

enum DisplayFormat {
    static func fileSize(_ bytes: Int64) -> String {
        var value = Double(max(0, bytes))
        let units = ["B", "kB", "MB", "GB"]
        var unit = 0
        while value >= 1000 && unit < units.count - 1 {
            value /= 1000
            unit += 1
        }
        let number = value.formatted(.number.grouping(.never).precision(.fractionLength(0...(unit == 0 ? 0 : 1))))
        return "\(number) \(units[unit])"
    }

    static func progress(fraction: Double, secondsRemaining: Double?) -> String {
        let percent = Int((min(1, max(0, fraction)) * 100).rounded(.down))
        guard let secondsRemaining, secondsRemaining.isFinite, secondsRemaining > 0 else { return "\(percent)%" }
        let seconds = Int(min(ceil(secondsRemaining), 365 * 24 * 60 * 60))
        let remaining: String
        if seconds < 60 {
            remaining = "\(seconds)s"
        } else if seconds < 3600 {
            remaining = "\(seconds / 60)m \(seconds % 60)s"
        } else {
            remaining = "\(seconds / 3600)h \((seconds % 3600) / 60)m"
        }
        return "\(percent)% · \(remaining) left"
    }
}

struct TransferETA {
    private var sampledAt: TimeInterval?
    private var sampleBytes: Int64 = 0
    private var lastBytes: Int64 = 0
    private var lastActivity: TimeInterval = 0
    private var bytesPerSecond: Double?

    mutating func remaining(written: Int64, total: Int64, now: TimeInterval) -> Double? {
        guard total > 0, written > 0, written < total else { return nil }
        if written < lastBytes { self = TransferETA() }
        if written > lastBytes { lastActivity = now }
        lastBytes = written
        guard let sampledAt else {
            self.sampledAt = now
            sampleBytes = written
            return nil
        }
        let elapsed = now - sampledAt
        if elapsed >= 0.75 {
            let rate = Double(max(0, written - sampleBytes)) / elapsed
            bytesPerSecond = bytesPerSecond.map { $0 * 0.65 + rate * 0.35 } ?? rate
            self.sampledAt = now
            sampleBytes = written
        }
        guard let rate = bytesPerSecond, rate > 0, now - lastActivity < 3 else { return nil }
        return Double(total - written) / rate
    }
}
