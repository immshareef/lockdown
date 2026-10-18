use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::AuthManager;
use crate::crypto::cipher::{decrypt_file, encrypt_file, FileMetadata};
use crate::error::Result as LdResult;
use crate::fileutil::{secure_delete, unique_path, write_atomic};
use crate::scanner::{Scanner, ScannedFile};
use crate::stealth::{apply_ghost, ensure_vault_dir, generate_disguised_name, get_vault_dir, StealthMode};

const AUTO_LOCK_AFTER: Duration = Duration::from_secs(300);
const MAX_ATTEMPTS_BEFORE_LOCKOUT: u32 = 3;
const NAME_COLLISION_ATTEMPTS: usize = 16;

type ScanResult = LdResult<(Vec<ScannedFile>, Vec<ScannedFile>)>;

pub struct LockdownApp {
    base_dir: PathBuf,
    ctx: egui::Context,
    auth: AuthManager,

    // Auth state
    password: String,
    confirm_password: String,
    show_password: bool,
    password_key: Option<Zeroizing<[u8; 32]>>,
    authenticated: bool,
    first_run: bool,
    failed_attempts: u32,
    locked_out_until: Option<Instant>,
    last_activity: Instant,

    // File lists
    unencrypted_files: Vec<ScannedFile>,
    encrypted_files: Vec<ScannedFile>,
    selected_unencrypted: Option<usize>,
    selected_encrypted: Option<usize>,

    // Settings
    stealth_mode: StealthMode,
    recursive_scan: bool,

    // Feedback
    status_message: String,
    error_message: Option<String>,

    // Background scanning
    scan_tx: mpsc::Sender<ScanResult>,
    scan_rx: mpsc::Receiver<ScanResult>,
    scan_pending: bool,

    // Delete confirmation: (path, display name, was_encrypted)
    pending_delete: Option<(PathBuf, String, bool)>,
}

impl LockdownApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let auth = AuthManager::new(&base_dir);
        let first_run = auth.is_first_run();
        let (scan_tx, scan_rx) = mpsc::channel();

        Self {
            base_dir,
            ctx: cc.egui_ctx.clone(),
            auth,
            password: String::new(),
            confirm_password: String::new(),
            show_password: false,
            password_key: None,
            authenticated: false,
            first_run,
            failed_attempts: 0,
            locked_out_until: None,
            last_activity: Instant::now(),
            unencrypted_files: Vec::new(),
            encrypted_files: Vec::new(),
            selected_unencrypted: None,
            selected_encrypted: None,
            stealth_mode: StealthMode::default(),
            recursive_scan: false,
            status_message: "Ready".to_string(),
            error_message: None,
            scan_tx,
            scan_rx,
            scan_pending: false,
            pending_delete: None,
        }
    }

    // ---------- background scan ----------

    fn request_scan(&mut self) {
        if self.scan_pending {
            return;
        }
        self.scan_pending = true;

        let base_dir = self.base_dir.clone();
        let recursive = self.recursive_scan;
        let tx = self.scan_tx.clone();
        let ctx = self.ctx.clone();

        thread::spawn(move || {
            let result = Scanner::new(base_dir).with_recursive(recursive).scan();
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    fn poll_scan(&mut self) {
        while let Ok(result) = self.scan_rx.try_recv() {
            self.scan_pending = false;
            match result {
                Ok((unencrypted, encrypted)) => {
                    self.status_message = format!(
                        "Scanned: {} unencrypted, {} encrypted",
                        unencrypted.len(),
                        encrypted.len()
                    );
                    self.unencrypted_files = unencrypted;
                    self.encrypted_files = encrypted;
                    // Indices are stale after a rescan.
                    self.selected_unencrypted = None;
                    self.selected_encrypted = None;
                }
                Err(e) => {
                    self.error_message = Some(format!("Scan failed: {}", e));
                }
            }
        }
    }

    // ---------- session ----------

    fn lock(&mut self, reason: &str) {
        self.password_key = None; // Zeroizing drop wipes the key.
        self.password.zeroize();
        self.confirm_password.zeroize();
        self.authenticated = false;
        self.selected_unencrypted = None;
        self.selected_encrypted = None;
        self.unencrypted_files.clear();
        self.encrypted_files.clear();
        self.status_message = reason.to_string();
    }

    fn on_authenticated(&mut self, key: Zeroizing<[u8; 32]>) {
        self.password_key = Some(key);
        self.authenticated = true;
        self.failed_attempts = 0;
        self.locked_out_until = None;
        self.last_activity = Instant::now();
        self.password.zeroize();
        self.confirm_password.zeroize();
        self.request_scan();
    }

    fn register_failed_attempt(&mut self) {
        self.failed_attempts += 1;
        if self.failed_attempts >= MAX_ATTEMPTS_BEFORE_LOCKOUT {
            let shift = (self.failed_attempts - MAX_ATTEMPTS_BEFORE_LOCKOUT).min(4);
            let secs = (1u64 << shift).min(30);
            self.locked_out_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    fn lockout_remaining(&self) -> Option<Duration> {
        self.locked_out_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
    }

    // ---------- crypto operations ----------

    fn encrypt_selected(&mut self) {
        let Some(idx) = self.selected_unencrypted else {
            self.error_message = Some("No file selected for encryption".to_string());
            return;
        };
        let Some(file) = self.unencrypted_files.get(idx).cloned() else {
            return;
        };
        let Some(password_key) = self.password_key.clone() else {
            self.error_message = Some("Not authenticated".to_string());
            return;
        };

        let plaintext = match std::fs::read(&file.path) {
            Ok(p) => Zeroizing::new(p),
            Err(e) => {
                self.error_message = Some(format!("Failed to read file: {}", e));
                return;
            }
        };

        let metadata = FileMetadata {
            original_name: file.name.clone(),
            original_path: file.path.to_string_lossy().to_string(),
            original_size: file.size,
            encrypted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let serialized = match encrypt_file(&plaintext, &metadata, &password_key[..]) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.error_message = Some(format!("Encryption failed: {}", e));
                return;
            }
        };

        let target_dir = file
            .path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| self.base_dir.clone());

        let target_path = match self.stealth_mode {
            StealthMode::Disguise | StealthMode::Ghost => {
                match unique_path(&target_dir, generate_disguised_name, NAME_COLLISION_ATTEMPTS) {
                    Ok(p) => p,
                    Err(e) => {
                        self.error_message = Some(format!("Naming failed: {}", e));
                        return;
                    }
                }
            }
            StealthMode::Hide => {
                let vault = match ensure_vault_dir(&self.base_dir) {
                    Ok(v) => v,
                    Err(e) => {
                        self.error_message = Some(format!("Vault creation failed: {}", e));
                        return;
                    }
                };
                match unique_path(
                    &vault,
                    || format!("{:016x}.lock", rand::random::<u64>()),
                    NAME_COLLISION_ATTEMPTS,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        self.error_message = Some(format!("Naming failed: {}", e));
                        return;
                    }
                }
            }
        };

        if let Err(e) = write_atomic(&target_path, &serialized) {
            self.error_message = Some(format!("Write failed: {}", e));
            return;
        }

        if self.stealth_mode == StealthMode::Ghost {
            if let Err(e) = apply_ghost(&target_path) {
                self.error_message = Some(format!(
                    "Encrypted, but hiding failed for {}: {}",
                    target_path.display(),
                    e
                ));
            }
        }

        // Original is removed only after the encrypted copy is safely on disk.
        if let Err(e) = secure_delete(&file.path) {
            self.error_message = Some(format!(
                "Encrypted copy is at {}, but secure-deleting the original failed: {}",
                target_path.display(),
                e
            ));
            return;
        }

        self.status_message = format!("Encrypted: {}", file.name);
        self.selected_unencrypted = None;
        self.request_scan();
    }

    fn decrypt_selected(&mut self) {
        let Some(idx) = self.selected_encrypted else {
            self.error_message = Some("No file selected for decryption".to_string());
            return;
        };
        let Some(file) = self.encrypted_files.get(idx).cloned() else {
            return;
        };
        let Some(password_key) = self.password_key.clone() else {
            self.error_message = Some("Not authenticated".to_string());
            return;
        };

        let encrypted_data = match std::fs::read(&file.path) {
            Ok(d) => d,
            Err(e) => {
                self.error_message = Some(format!("Failed to read file: {}", e));
                return;
            }
        };

        let decrypted = match decrypt_file(&encrypted_data, &password_key[..]) {
            Ok(d) => d,
            Err(e) => {
                self.error_message = Some(format!("Decryption failed: {}", e));
                return;
            }
        };

        // Restore next to the encrypted file; vault contents restore to the base dir.
        let vault = get_vault_dir(&self.base_dir);
        let parent = file.path.parent();
        let output_dir = if parent == Some(vault.as_path()) {
            self.base_dir.clone()
        } else {
            parent
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| self.base_dir.clone())
        };

        let output_path = output_dir.join(&decrypted.metadata.original_name);
        if output_path.exists() {
            self.error_message = Some(format!(
                "Cannot restore: {} already exists",
                output_path.display()
            ));
            return;
        }

        if let Err(e) = write_atomic(&output_path, &decrypted.plaintext) {
            self.error_message = Some(format!("Failed to write decrypted file: {}", e));
            return;
        }

        if let Err(e) = std::fs::remove_file(&file.path) {
            self.error_message = Some(format!(
                "Restored {}, but removing the encrypted file failed: {}",
                decrypted.metadata.original_name, e
            ));
            return;
        }

        self.status_message = format!("Decrypted: {}", decrypted.metadata.original_name);
        self.selected_encrypted = None;
        self.request_scan();
    }

    // ---------- auth screen ----------

    fn try_setup(&mut self) {
        if self.password.is_empty() {
            self.error_message = Some("Password cannot be empty".to_string());
            return;
        }
        if self.password != self.confirm_password {
            self.error_message = Some("Passwords do not match".to_string());
            return;
        }
        match self.auth.setup_password(&self.password) {
            Ok(key) => {
                self.first_run = false;
                self.error_message = None;
                self.on_authenticated(key);
            }
            Err(e) => {
                self.error_message = Some(format!("Setup failed: {}", e));
            }
        }
    }

    fn try_unlock(&mut self) {
        if self.lockout_remaining().is_some() {
            return;
        }
        match self.auth.unlock(&self.password) {
            Ok(Some(key)) => {
                self.error_message = None;
                self.on_authenticated(key);
            }
            Ok(None) => {
                self.register_failed_attempt();
                self.error_message = Some("Incorrect password".to_string());
            }
            Err(e) => {
                self.error_message = Some(format!("Auth error: {}", e));
            }
        }
    }

    fn password_field(&mut self, ui: &mut egui::Ui, label: &str, value: &mut String) {
        ui.horizontal(|ui| {
            ui.label(label);
            if self.show_password {
                ui.text_edit_singleline(value);
            } else {
                ui.add(egui::TextEdit::singleline(value).password(true));
            }
        });
    }

    fn handle_auth(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.heading("Lockdown");
                ui.add_space(20.0);

                if self.first_run {
                    ui.label("Create a master password");
                    ui.add_space(10.0);

                    let mut password = std::mem::take(&mut self.password);
                    let mut confirm = std::mem::take(&mut self.confirm_password);
                    self.password_field(ui, "Password:", &mut password);
                    self.password_field(ui, "Confirm:", &mut confirm);
                    self.password = password;
                    self.confirm_password = confirm;

                    if ui.button("👁 Show").clicked() {
                        self.show_password = !self.show_password;
                    }
                    ui.add_space(10.0);

                    let submit = ui.button("Set Password").clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if submit {
                        self.try_setup();
                    }
                } else {
                    ui.label("Enter your password");
                    ui.add_space(10.0);

                    let mut password = std::mem::take(&mut self.password);
                    self.password_field(ui, "Password:", &mut password);
                    self.password = password;

                    if ui.button("👁 Show").clicked() {
                        self.show_password = !self.show_password;
                    }
                    ui.add_space(10.0);

                    if let Some(remaining) = self.lockout_remaining() {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            format!("Too many attempts. Retry in {}s.", remaining.as_secs() + 1),
                        );
                        ctx.request_repaint_after(Duration::from_millis(250));
                    } else {
                        let submit = ui.button("Unlock").clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if submit {
                            self.try_unlock();
                        }
                    }
                }

                if let Some(err) = &self.error_message {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::RED, err);
                }
            });
        });
    }

    // ---------- main screen ----------

    fn file_row(
        ui: &mut egui::Ui,
        file: &ScannedFile,
        selected: bool,
        icon: &str,
        action_label: &str,
    ) -> (bool, bool, bool) {
        let response = ui.selectable_label(
            selected,
            format!("{} {} ({:.1} KB)", icon, file.name, file.size as f64 / 1024.0),
        );
        let clicked = response.clicked();

        let mut action = false;
        let mut delete = false;
        response.context_menu(|ui| {
            if ui.button(action_label).clicked() {
                action = true;
                ui.close_menu();
            }
            if ui.button("Delete").clicked() {
                delete = true;
                ui.close_menu();
            }
        });

        (clicked, action, delete)
    }

    fn show_file_panes(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.heading(format!("Unencrypted ({})", self.unencrypted_files.len()));
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut clicked_idx = None;
                    let mut action_idx = None;
                    let mut delete_idx = None;

                    for (idx, file) in self.unencrypted_files.iter().enumerate() {
                        let (clicked, action, delete) = Self::file_row(
                            ui,
                            file,
                            self.selected_unencrypted == Some(idx),
                            "📄",
                            "Encrypt",
                        );
                        if clicked {
                            clicked_idx = Some(idx);
                        }
                        if action {
                            action_idx = Some(idx);
                        }
                        if delete {
                            delete_idx = Some(idx);
                        }
                    }

                    if let Some(idx) = clicked_idx {
                        self.selected_unencrypted = Some(idx);
                        self.selected_encrypted = None;
                    }
                    if let Some(idx) = action_idx {
                        self.selected_unencrypted = Some(idx);
                        self.encrypt_selected();
                    }
                    if let Some(idx) = delete_idx {
                        let f = &self.unencrypted_files[idx];
                        self.pending_delete = Some((f.path.clone(), f.name.clone(), false));
                    }
                });
            });

        egui::SidePanel::right("right_panel")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.heading(format!("Encrypted ({})", self.encrypted_files.len()));
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut clicked_idx = None;
                    let mut action_idx = None;
                    let mut delete_idx = None;

                    for (idx, file) in self.encrypted_files.iter().enumerate() {
                        let (clicked, action, delete) = Self::file_row(
                            ui,
                            file,
                            self.selected_encrypted == Some(idx),
                            "🔒",
                            "Decrypt",
                        );
                        if clicked {
                            clicked_idx = Some(idx);
                        }
                        if action {
                            action_idx = Some(idx);
                        }
                        if delete {
                            delete_idx = Some(idx);
                        }
                    }

                    if let Some(idx) = clicked_idx {
                        self.selected_encrypted = Some(idx);
                        self.selected_unencrypted = None;
                    }
                    if let Some(idx) = action_idx {
                        self.selected_encrypted = Some(idx);
                        self.decrypt_selected();
                    }
                    if let Some(idx) = delete_idx {
                        let f = &self.encrypted_files[idx];
                        self.pending_delete = Some((f.path.clone(), f.name.clone(), true));
                    }
                });
            });
    }

    fn show_delete_confirm(&mut self, ctx: &egui::Context) {
        let Some((path, name, was_encrypted)) = self.pending_delete.clone() else {
            return;
        };

        let mut confirm = false;
        let mut cancel = false;

        egui::Window::new("Confirm delete")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!(
                    "Permanently delete \"{}\"?{}",
                    name,
                    if was_encrypted {
                        " Its contents will be unrecoverable."
                    } else {
                        ""
                    }
                ));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Delete").clicked() {
                        confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if confirm {
            match secure_delete(&path) {
                Ok(_) => self.status_message = format!("Deleted: {}", name),
                Err(e) => self.error_message = Some(format!("Delete failed: {}", e)),
            }
            self.pending_delete = None;
            self.request_scan();
        } else if cancel {
            self.pending_delete = None;
        }
    }
}

impl eframe::App for LockdownApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();

        if !self.authenticated {
            self.handle_auth(ctx);
            return;
        }

        // Auto-lock on idle.
        if ctx.input(|i| !i.raw.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        let idle_for = self.last_activity.elapsed();
        if idle_for >= AUTO_LOCK_AFTER {
            self.lock("Auto-locked after inactivity");
            return;
        }
        ctx.request_repaint_after(Duration::from_secs(5));

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Lockdown");
                ui.separator();
                ui.label(format!("📁 {}", self.base_dir.display()));
                ui.separator();

                egui::ComboBox::from_label("Stealth Mode")
                    .selected_text(format!("{}", self.stealth_mode))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.stealth_mode, StealthMode::Disguise, "Disguise");
                        ui.selectable_value(&mut self.stealth_mode, StealthMode::Hide, "Hide");
                        ui.selectable_value(&mut self.stealth_mode, StealthMode::Ghost, "Ghost");
                    });

                if ui.checkbox(&mut self.recursive_scan, "Recursive").changed() {
                    self.request_scan();
                }

                if ui.button("🔄 Refresh").clicked() {
                    self.request_scan();
                }
                if self.scan_pending {
                    ui.spinner();
                }
            });
        });

        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_message);
                ui.separator();
                ui.label(format!(
                    "{} files",
                    self.unencrypted_files.len() + self.encrypted_files.len()
                ));
                ui.separator();

                let remaining = AUTO_LOCK_AFTER.saturating_sub(idle_for);
                ui.label(format!(
                    "🔓 Unlocked (locks in {}:{:02})",
                    remaining.as_secs() / 60,
                    remaining.as_secs() % 60
                ));
                if ui.button("Lock now").clicked() {
                    self.lock("Locked");
                }
            });
        });

        self.show_file_panes(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);

                if self.selected_unencrypted.is_some() {
                    if ui.button("🔒 Encrypt Selected →").clicked() {
                        self.encrypt_selected();
                    }
                } else if self.selected_encrypted.is_some() {
                    if ui.button("← 🔓 Decrypt Selected").clicked() {
                        self.decrypt_selected();
                    }
                } else {
                    ui.label("Select a file to encrypt or decrypt");
                }

                if let Some(err) = &self.error_message {
                    ui.add_space(20.0);
                    ui.colored_label(egui::Color32::RED, err);
                    if ui.button("Dismiss").clicked() {
                        self.error_message = None;
                    }
                }
            });
        });

        self.show_delete_confirm(ctx);
    }
}
