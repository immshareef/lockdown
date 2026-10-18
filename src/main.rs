use eframe::egui;
use lockdown::ui::LockdownApp;

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
        Box::new(|cc| Box::new(LockdownApp::new(cc))),
    )
}
