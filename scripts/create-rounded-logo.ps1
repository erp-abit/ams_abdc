Add-Type -AssemblyName System.Drawing

$sourcePath = Join-Path $PSScriptRoot '..\public\logo.png'
$outputPath = Join-Path $PSScriptRoot '..\public\logo-rounded.png'
$source = [System.Drawing.Image]::FromFile($sourcePath)
$bitmap = New-Object System.Drawing.Bitmap 256, 256, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)

try {
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

    $circle = New-Object System.Drawing.Drawing2D.GraphicsPath
    $circle.AddEllipse(0, 0, 256, 256)
    $graphics.SetClip($circle)

    $sourceSquare = New-Object System.Drawing.RectangleF 0, 30.5, 266, 266
    $destination = New-Object System.Drawing.RectangleF 0, 0, 256, 256
    $graphics.DrawImage($source, $destination, $sourceSquare, [System.Drawing.GraphicsUnit]::Pixel)
    $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    if ($circle) { $circle.Dispose() }
    $graphics.Dispose()
    $bitmap.Dispose()
    $source.Dispose()
}
