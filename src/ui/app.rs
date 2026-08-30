use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;

use crate::auth::AuthManager;
use crate::crypto::cipher::{
    decrypt_file, encrypt_file, serialize_encrypted_with_sk, FileMetadata,
};
use crate::scanner::{Scanner, ScannedFile};
use crate::stealth::{
    apply_disguise, apply_ghost, ensure_vault_dir, remove_disguise, remove_ghost,
    StealthMode,
};

pub struct LockdownApp {
    base_dir: PathBuf,
    auth: AuthManager,
    password: String,
    password_key: Option<[u8; 32]>,
    authenticated: bool,
    first_run: bool,
    confirm_password: String,
    show_password: bool,

    unencrypted_files: Vec<ScannedFile>,
    encrypted_files: Vec<ScannedFile>,

    selected_unencrypted: Option<usize>,
    selected_encrypted: Option<usize>,

    stealth_mode: StealthMode,
    recursive_scan: bool,

    status_message: String,
    error_message: Option<String>,

    scan_rx: mpsc::Receiver<(Vec<ScannedFile>, Vec<ScannedFile>)>,
}

impl LockdownApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let auth = AuthManager::new(&base_dir);
        let first_run = auth.is_first_run();

        let (_scan_tx, scan_rx) = mpsc::channel();

        let app = Self {
            base_dir,
            auth,
            password: String::new(),
            password_key: None,
            authenticated: false,
            first_run,
            confirm_password: String::new(),
            show_password: false,
            unencrypted_files: Vec::new(),
            encrypted_files: Vec::new(),
            selected_unencrypted: None,
            selected_encrypted: None,
            stealth_mode: StealthMode::default(),
            recursive_scan: false,
            status_message: "Ready".to_string(),
            error_message: None,
            scan_rx,
        };

        app.configure_fonts(&cc.egui_ctx);
        app
    }

    fn configure_fonts(&self, _ctx: &egui::Context) {
        // Use default fonts; can be extended with custom fonts
    }

    fn refresh_scan(&mut self) {
        let scanner = Scanner::new(self.base_dir.clone())
            .with_recursive(self.recursive_scan);

        match scanner.scan() {
            Ok((unencrypted, encrypted)) => {
                self.unencrypted_files = unencrypted;
                self.encrypted_files = encrypted;
                self.status_message = format!(
                    "Scanned: {} unencrypted, {} encrypted",
                    self.unencrypted_files.len(),
                    self.encrypted_files.len()
                );
            }
            Err(e) => {
                self.error_message = Some(format!("Scan failed: {}", e));
            }
        }
    }

    fn encrypt_selected(&mut self) {
        let Some(idx) = self.selected_unencrypted else {
            self.error_message = Some("No file selected for encryption".to_string());
            return;
        };

        let Some(file) = self.unencrypted_files.get(idx) else {
            return;
        };

        let Some(ref password_key) = self.password_key else {
            self.error_message = Some("Not authenticated".to_string());
            return;
        };

        let plaintext = match std::fs::read(&file.path) {
            Ok(p) => p,
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

        let encrypted = match encrypt_file(&plaintext, &metadata, password_key) {
            Ok(r) => r,
            Err(e) => {
                self.error_message = Some(format!("Encryption failed: {}", e));
                return;
            }
        };

        let serialized = serialize_encrypted_with_sk(&encrypted);

        // Determine the target directory: same folder as the original file
        let target_dir = file.path.parent().unwrap_or(&self.base_dir).to_path_buf();

        let _result_path = match self.stealth_mode {
            StealthMode::Disguise => {
                match apply_disguise(&serialized, &target_dir) {
                    Ok(p) => p,
                    Err(e) => {
                        self.error_message = Some(format!("Disguise failed: {}", e));
                        return;
                    }
                }
            }
            StealthMode::Hide => {
                let vault = match ensure_vault_dir(&target_dir) {
                    Ok(v) => v,
                    Err(e) => {
                        self.error_message = Some(format!("Vault creation failed: {}", e));
                        return;
                    }
                };
                let path = vault.join(format!("{}.lock", rand::random::<u64>()));
                match std::fs::write(&path, &serialized) {
                    Ok(_) => path,
                    Err(e) => {
                        self.error_message = Some(format!("Write failed: {}", e));
                        return;
                    }
                }
            }
            StealthMode::Ghost => {
                let path = target_dir.join(format!("{}.lock", file.name));
                match std::fs::write(&path, &serialized) {
                    Ok(_) => {
                        if let Err(e) = apply_ghost(&path) {
                            self.error_message = Some(format!("Ghost attribute failed: {}", e));
                        }
                        path
                    }
                    Err(e) => {
                        self.error_message = Some(format!("Write failed: {}", e));
                        return;
                    }
                }
            }
        };

        if let Err(e) = std::fs::remove_file(&file.path) {
            self.error_message = Some(format!("Failed to remove original: {}", e));
            return;
        }

        self.status_message = format!("Encrypted: {}", file.name);
        self.selected_unencrypted = None;
        self.refresh_scan();
    }

    fn decrypt_selected(&mut self) {
        let Some(idx) = self.selected_encrypted else {
            self.error_message = Some("No file selected for decryption".to_string());
            return;
        };

        let Some(file) = self.encrypted_files.get(idx) else {
            return;
        };

        let Some(ref password_key) = self.password_key else {
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

        let decrypted = match decrypt_file(&encrypted_data, password_key) {
            Ok(d) => d,
            Err(e) => {
                self.error_message = Some(format!("Decryption failed: {}", e));
                return;
            }
        };

        // Determine output path: same folder as the encrypted file, with original name
        let output_dir = file.path.parent().unwrap_or(&self.base_dir);
        let output_path = output_dir.join(&decrypted.metadata.original_name);
        if let Err(e) = std::fs::write(&output_path, &decrypted.plaintext) {
            self.error_message = Some(format!("Failed to write decrypted file: {}", e));
            return;
        }

        match self.stealth_mode {
            StealthMode::Disguise => {
                let _ = remove_disguise(&file.path);
            }
            StealthMode::Hide => {
                let _ = std::fs::remove_file(&file.path);
            }
            StealthMode::Ghost => {
                let _ = remove_ghost(&file.path);
                let _ = std::fs::remove_file(&file.path);
            }
        }

        self.status_message = format!("Decrypted: {}", decrypted.metadata.original_name);
        self.selected_encrypted = None;
        self.refresh_scan();
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

                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        if self.show_password {
                            ui.text_edit_singleline(&mut self.password);
                        } else {
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        }
                        if ui.button("👁").clicked() {
                            self.show_password = !self.show_password;
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Confirm:");
                        if self.show_password {
                            ui.text_edit_singleline(&mut self.confirm_password);
                        } else {
                            ui.add(egui::TextEdit::singleline(&mut self.confirm_password).password(true));
                        }
                    });

                    ui.add_space(10.0);

                    if ui.button("Set Password").clicked() {
                        if self.password.is_empty() {
                            self.error_message = Some("Password cannot be empty".to_string());
                        } else if self.password != self.confirm_password {
                            self.error_message = Some("Passwords do not match".to_string());
                        } else {
                            match self.auth.setup_password(&self.password) {
                                Ok(_) => {
                                    self.password_key = Some(
                                        self.auth.derive_password_key(&self.password).unwrap_or([0u8; 32])
                                    );
                                    self.authenticated = true;
                                    self.first_run = false;
                                    self.refresh_scan();
                                }
                                Err(e) => {
                                    self.error_message = Some(format!("Setup failed: {}", e));
                                }
                            }
                        }
                    }
                } else {
                    ui.label("Enter your password");
                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        if self.show_password {
                            ui.text_edit_singleline(&mut self.password);
                        } else {
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        }
                        if ui.button("👁").clicked() {
                            self.show_password = !self.show_password;
                        }
                    });

                    ui.add_space(10.0);

                    if ui.button("Unlock").clicked() {
                        match self.auth.verify_password(&self.password) {
                            Ok(true) => {
                                self.password_key = Some(
                                    self.auth.derive_password_key(&self.password).unwrap_or([0u8; 32])
                                );
                                self.authenticated = true;
                                self.refresh_scan();
                            }
                            Ok(false) => {
                                self.error_message = Some("Incorrect password".to_string());
                            }
                            Err(e) => {
                                self.error_message = Some(format!("Auth error: {}", e));
                            }
                        }
                    }
                }

                if let Some(ref err) = self.error_message {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::RED, err);
                }
            });
        });
    }
}

impl eframe::App for LockdownApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.authenticated {
            self.handle_auth(ctx);
            return;
        }

        // Handle async scan results
        while let Ok((unencrypted, encrypted)) = self.scan_rx.try_recv() {
            self.unencrypted_files = unencrypted;
            self.encrypted_files = encrypted;
        }

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

                ui.checkbox(&mut self.recursive_scan, "Recursive");

                if ui.button("🔄 Refresh").clicked() {
                    self.refresh_scan();
                }
            });
        });

        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_message);
                ui.separator();
                ui.label(format!("{} files", self.unencrypted_files.len() + self.encrypted_files.len()));
                ui.separator();
                ui.label("🔓 Unlocked");
            });
        });

        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.heading(format!("Unencrypted ({})", self.unencrypted_files.len()));
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut encrypt_idx = None;
                    let mut delete_idx = None;
                    for (idx, file) in self.unencrypted_files.iter().enumerate() {
                        let selected = self.selected_unencrypted == Some(idx);
                        let response = ui.selectable_label(
                            selected,
                            format!("📄 {} ({:.1} KB)", file.name, file.size as f64 / 1024.0),
                        );

                        if response.clicked() {
                            self.selected_unencrypted = Some(idx);
                            self.selected_encrypted = None;
                        }

                        response.context_menu(|ui| {
                            if ui.button("Encrypt").clicked() {
                                encrypt_idx = Some(idx);
                                ui.close_menu();
                            }
                            if ui.button("Delete").clicked() {
                                delete_idx = Some(idx);
                                ui.close_menu();
                            }
                        });
                    }
                    if let Some(idx) = encrypt_idx {
                        self.selected_unencrypted = Some(idx);
                        self.encrypt_selected();
                    }
                    if let Some(idx) = delete_idx {
                        let _ = std::fs::remove_file(&self.unencrypted_files[idx].path);
                        self.refresh_scan();
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
                    let mut decrypt_idx = None;
                    let mut delete_idx = None;
                    for (idx, file) in self.encrypted_files.iter().enumerate() {
                        let selected = self.selected_encrypted == Some(idx);
                        let response = ui.selectable_label(
                            selected,
                            format!("🔒 {} ({:.1} KB)", file.name, file.size as f64 / 1024.0),
                        );

                        if response.clicked() {
                            self.selected_encrypted = Some(idx);
                            self.selected_unencrypted = None;
                        }

                        response.context_menu(|ui| {
                            if ui.button("Decrypt").clicked() {
                                decrypt_idx = Some(idx);
                                ui.close_menu();
                            }
                            if ui.button("Delete").clicked() {
                                delete_idx = Some(idx);
                                ui.close_menu();
                            }
                        });
                    }
                    if let Some(idx) = decrypt_idx {
                        self.selected_encrypted = Some(idx);
                        self.decrypt_selected();
                    }
                    if let Some(idx) = delete_idx {
                        let _ = std::fs::remove_file(&self.encrypted_files[idx].path);
                        self.refresh_scan();
                    }
                });
            });

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

                if let Some(ref err) = self.error_message {
                    ui.add_space(20.0);
                    ui.colored_label(egui::Color32::RED, err);
                    if ui.button("Dismiss").clicked() {
                        self.error_message = None;
                    }
                }
            });
        });
    }
}
