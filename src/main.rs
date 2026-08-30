mod auth;
mod crypto;
mod error;
mod scanner;
mod stealth;
mod ui;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
            .with_min_inner_size([700.0, 400.0])
            .with_title("Lockdown"),
        ..Default::default()
    };

    eframe::run_native(
        "Lockdown",
        options,
        Box::new(|cc| Box::new(ui::LockdownApp::new(cc))),
    )
}
