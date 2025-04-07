pub fn build_front_end() -> String {
    let html_str: &'static str = r#"
    <!DOCTYPE html>
    <html lang="id">
    <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Landing Page - DaisyUI</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
        plugins: [window.daisyui],
        }
    </script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.24/dist/full.min.css" rel="stylesheet" type="text/css" />
    </head>
    <body class="bg-base-100 text-base-content">

    <!-- Hero Section -->
    <section class="hero min-h-screen bg-primary text-primary-content">
        <div class="hero-content text-center">
        <div class="max-w-md">
            <h1 class="text-5xl font-bold">Selamat Datang!</h1>
            <p class="py-6">Kami hadir untuk membantu Anda membangun solusi digital yang cepat, handal, dan user-friendly.</p>
            <a href="fitur" class="btn btn-secondary">Jelajahi Fitur</a>
        </div>
        </div>
    </section>

    <!-- Features Section -->
    <section id="fitur" class="py-16 px-4 bg-base-200">
        <div class="text-center mb-10">
        <h2 class="text-3xl font-bold">Fitur Unggulan</h2>
        <p class="text-gray-500">Kenapa harus memilih layanan kami?</p>
        </div>
        <div class="flex flex-col md:flex-row justify-center gap-8 max-w-5xl mx-auto">
        <div class="card w-full md:w-1/3 bg-white shadow-md">
            <div class="card-body items-center text-center">
            <h3 class="card-title">Cepat & Andal</h3>
            <p>Performa tinggi dengan infrastruktur terbaik untuk efisiensi maksimal.</p>
            </div>
        </div>
        <div class="card w-full md:w-1/3 bg-white shadow-md">
            <div class="card-body items-center text-center">
            <h3 class="card-title">Desain Responsif</h3>
            <p>Tampilan optimal di semua perangkat—desktop, tablet, hingga mobile.</p>
            </div>
        </div>
        <div class="card w-full md:w-1/3 bg-white shadow-md">
            <div class="card-body items-center text-center">
            <h3 class="card-title">Dukungan 24/7</h3>
            <p>Tim support kami siap membantu Anda kapan pun dibutuhkan.</p>
            </div>
        </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer footer-center p-6 bg-base-300 text-base-content">
        <aside>
        <p>&copy; 2025 Layanan Kami. Semua Hak Dilindungi.</p>
        </aside>
    </footer>

    </body>
    </html>
    "#;

    html_str.to_string()
}
