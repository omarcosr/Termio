# Draws the app icon (assets/icon.png, 256 px): an amber rounded tile with a terminal prompt.
#   powershell -ExecutionPolicy Bypass -File scripts/make-icon.ps1
Add-Type -AssemblyName System.Drawing
$size = 256
$bmp = New-Object System.Drawing.Bitmap $size, $size
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([System.Drawing.Color]::Transparent)
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$r = 56; $m = 8; $w = $size - 2 * $m
$path.AddArc($m, $m, $r, $r, 180, 90); $path.AddArc($m + $w - $r, $m, $r, $r, 270, 90)
$path.AddArc($m + $w - $r, $m + $w - $r, $r, $r, 0, 90); $path.AddArc($m, $m + $w - $r, $r, $r, 90, 90)
$path.CloseFigure()
$fill = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.Point 0, 0), (New-Object System.Drawing.Point 0, $size), ([System.Drawing.Color]::FromArgb(255, 247, 181, 92)), ([System.Drawing.Color]::FromArgb(255, 230, 140, 30))
$g.FillPath($fill, $path)
$ink = [System.Drawing.Color]::FromArgb(255, 27, 18, 3)
$pen = New-Object System.Drawing.Pen $ink, 22
$pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
$g.DrawLines($pen, [System.Drawing.Point[]]@((New-Object System.Drawing.Point 70, 82), (New-Object System.Drawing.Point 118, 128), (New-Object System.Drawing.Point 70, 174)))
$g.DrawLine($pen, 136, 176, 190, 176)
$out = Join-Path $PSScriptRoot '..\assets'
New-Item -ItemType Directory -Force $out | Out-Null
$bmp.Save((Join-Path $out 'icon.png'), [System.Drawing.Imaging.ImageFormat]::Png)
