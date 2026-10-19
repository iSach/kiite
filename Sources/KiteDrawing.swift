import AppKit

enum KiteAppearance: Equatable {
    case ready
    case hover
    case uploading(CGFloat)
    case success
    case attention
}

enum KiteDrawing {
    // Let the status-bar button adapt the neutral ink to its actual background.
    // The colored interior is drawn separately, without template tinting.
    static func templateImage(hover: Bool) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
            drawNeutral(in: rect, hover: hover, dark: false)
            return true
        }
        image.isTemplate = true
        return image
    }

    static func fillImage(appearance: KiteAppearance) -> NSImage? {
        switch appearance {
        case .ready, .hover: return nil
        default: break
        }
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
            drawFill(in: rect, appearance: appearance)
            return true
        }
        image.isTemplate = false
        return image
    }

    static func image(appearance: KiteAppearance, dark: Bool) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
            draw(in: rect, appearance: appearance, dark: dark)
            return true
        }
        image.isTemplate = false
        return image
    }

    static func draw(in bounds: NSRect, appearance: KiteAppearance, dark: Bool) {
        drawNeutral(in: bounds, hover: appearance == .hover, dark: dark)
        drawFill(in: bounds, appearance: appearance)
    }

    private static func drawNeutral(in bounds: NSRect, hover: Bool, dark: Bool) {
        guard let ctx = NSGraphicsContext.current?.cgContext else { return }
        let rect = bounds.insetBy(dx: 2, dy: 1)
        let body = bodyPath(in: rect)
        let tail = tailPath(in: rect)

        let ink = dark
            ? NSColor(calibratedWhite: 1, alpha: 0.92)
            : NSColor(calibratedWhite: 0, alpha: 0.88)
        let idleFill = dark
            ? NSColor(calibratedWhite: 1, alpha: 0.34)
            : NSColor(calibratedWhite: 0, alpha: 0.28)
        ctx.saveGState()
        body.addClip()
        idleFill.setFill()
        body.fill()
        ctx.restoreGState()

        let stroke = hover ? ink : ink.withAlphaComponent(0.8)
        let width: CGFloat = hover ? 1.8 : 1.15
        stroke.setStroke()
        body.lineWidth = width
        body.lineJoinStyle = .round
        body.stroke()
        tail.lineWidth = width
        tail.lineCapStyle = .round
        tail.stroke()

        // Cross spar so the diamond reads as a kite at menu-bar size.
        let spar = NSBezierPath()
        let midY = rect.minY + rect.height * 0.62
        spar.move(to: NSPoint(x: rect.minX + rect.width * 0.18, y: midY))
        spar.line(to: NSPoint(x: rect.minX + rect.width * 0.82, y: midY))
        spar.lineWidth = 0.8
        ink.withAlphaComponent(0.55).setStroke()
        spar.stroke()
    }

    private static func drawFill(in bounds: NSRect, appearance: KiteAppearance) {
        guard let ctx = NSGraphicsContext.current?.cgContext else { return }
        let fraction: CGFloat
        let color: NSColor
        switch appearance {
        case .uploading(let progress):
            fraction = min(1, max(0, progress))
            color = NSColor(srgbRed: 0.15, green: 0.85, blue: 0.32, alpha: 1)
        case .success:
            fraction = 1
            color = NSColor(srgbRed: 0.22, green: 0.48, blue: 0.98, alpha: 1)
        case .attention:
            fraction = 1
            color = NSColor(srgbRed: 0.92, green: 0.32, blue: 0.24, alpha: 1)
        case .ready, .hover:
            return
        }
        let rect = bounds.insetBy(dx: 2, dy: 1)
        let interior = Diamond(in: rect, inset: 0.65)
        let sparBottom = rect.minY + rect.height * 0.62 - 0.45
        let sparTop = sparBottom + 0.9
        ctx.saveGState()
        interior.path.addClip()
        // Leave the neutral cross spar visible above the colored interior.
        let sparClip = CGMutablePath()
        sparClip.addRect(bounds)
        sparClip.addRect(NSRect(x: rect.minX, y: sparBottom,
                                width: rect.width, height: 0.9))
        ctx.addPath(sparClip)
        ctx.clip(using: .evenOdd)
        color.setFill()
        NSRect(x: rect.minX, y: interior.bottom, width: rect.width,
               height: interior.fillLevel(fraction: fraction, excluding: sparBottom...sparTop) - interior.bottom).fill()
        ctx.restoreGState()
    }

    private static func bodyPath(in rect: NSRect) -> NSBezierPath {
        Diamond(in: rect).path
    }

    private static func tailPath(in rect: NSRect) -> NSBezierPath {
        let path = NSBezierPath()
        path.move(to: NSPoint(x: rect.midX, y: rect.minY + rect.height * 0.30))
        path.line(to: NSPoint(x: rect.midX + rect.width * 0.10, y: rect.minY + rect.height * 0.14))
        path.line(to: NSPoint(x: rect.midX - rect.width * 0.02, y: rect.minY + rect.height * 0.04))
        return path
    }

    private struct Diamond {
        let centerX: CGFloat
        let halfWidth: CGFloat
        let bottom: CGFloat
        let shoulder: CGFloat
        let top: CGFloat

        init(in rect: NSRect, inset: CGFloat = 0) {
            centerX = rect.midX
            let width = rect.width * 0.36
            let lower = rect.height * 0.32
            let upper = rect.height * 0.34
            bottom = rect.minY + rect.height * 0.30 + inset * hypot(width, lower) / width
            top = rect.minY + rect.height * 0.96 - inset * hypot(width, upper) / width
            halfWidth = width * (top - bottom) / (lower + upper)
            shoulder = (lower * top + upper * bottom) / (lower + upper)
        }

        var path: NSBezierPath {
            let path = NSBezierPath()
            path.move(to: NSPoint(x: centerX, y: top))
            path.line(to: NSPoint(x: centerX + halfWidth, y: shoulder))
            path.line(to: NSPoint(x: centerX, y: bottom))
            path.line(to: NSPoint(x: centerX - halfWidth, y: shoulder))
            path.close()
            return path
        }

        func fillLevel(fraction: CGFloat, excluding band: ClosedRange<CGFloat>) -> CGFloat {
            let height = top - bottom
            let lower = shoulder - bottom
            let upper = top - shoulder
            let bandStart = areaFraction(below: band.lowerBound)
            let bandArea = areaFraction(below: band.upperBound) - bandStart
            let coloredArea = fraction * (1 - bandArea)
            let area = coloredArea <= bandStart ? coloredArea : coloredArea + bandArea
            // Match the fraction of the diamond's area, rather than the full
            // icon height or a linear height through its tapered triangles.
            if area <= lower / height {
                return bottom + sqrt(area * height * lower)
            }
            return top - sqrt(max(0, 1 - area) * height * upper)
        }

        private func areaFraction(below level: CGFloat) -> CGFloat {
            let y = min(top, max(bottom, level))
            let height = top - bottom
            if y <= shoulder {
                return (y - bottom) * (y - bottom) / (height * (shoulder - bottom))
            }
            return 1 - (top - y) * (top - y) / (height * (top - shoulder))
        }
    }
}
