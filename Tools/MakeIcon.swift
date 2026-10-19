import AppKit

@main enum MakeIcon {
    static func main() throws {
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for size in [16, 32, 128, 256, 512] {
            for scale in [1, 2] {
                let pixels = size * scale
                let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
                NSGraphicsContext.saveGraphicsState()
                NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
                let context = NSGraphicsContext.current!.cgContext
                let canvas = CGFloat(pixels)
                NSColor(srgbRed: 0.95, green: 0.96, blue: 0.98, alpha: 1).setFill()
                NSBezierPath(roundedRect: NSRect(x: canvas * 0.04, y: canvas * 0.04, width: canvas * 0.92, height: canvas * 0.92),
                             xRadius: canvas * 0.20, yRadius: canvas * 0.20).fill()
                context.translateBy(x: canvas * 0.08, y: canvas * 0.08)
                context.scaleBy(x: canvas * 0.84 / 18, y: canvas * 0.84 / 18)
                KiteDrawing.draw(in: NSRect(x: 0, y: 0, width: 18, height: 18), appearance: .success, dark: false)
                NSGraphicsContext.restoreGraphicsState()
                let suffix = scale == 2 ? "@2x" : ""
                let file = directory.appendingPathComponent("icon_\(size)x\(size)\(suffix).png")
                try bitmap.representation(using: .png, properties: [:])!.write(to: file)
            }
        }
    }
}
