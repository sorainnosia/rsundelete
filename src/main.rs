#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod scanner;
mod recovery;

use eframe::egui;
use scanner::{DeletedFile, FileSystemScanner, disk_access};
use scanner::ntfs::NtfsScanner;
use scanner::exfat::ExfatScanner;
use recovery::FileRecovery;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<(), eframe::Error> {
    // Load icon from icon.ico file
    let icon_data = include_bytes!("../icon.ico");
    let icon = load_icon_from_ico(icon_data);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_title("Rust Undelete - File Recovery Tool")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "Rust Undelete",
        options,
        Box::new(|_cc| Ok(Box::new(RunDeleteApp::default()))),
    )
}

fn load_icon_from_ico(ico_data: &[u8]) -> egui::IconData {
    // Parse ICO file - ICO format has a header followed by image data
    // For simplicity, we'll try to extract the largest icon
    let image = image::load_from_memory(ico_data)
        .expect("Failed to load icon")
        .to_rgba8();

    let (width, height) = image.dimensions();
    let rgba = image.into_raw();

    egui::IconData {
        rgba,
        width: width as u32,
        height: height as u32,
    }
}

struct RunDeleteApp {
    // Input fields
    selected_drive: String,
    folder_path: String,
    filename_filter: String,

    // Scan results
    deleted_files: Arc<Mutex<Vec<DeletedFile>>>,
    is_scanning: Arc<Mutex<bool>>,
    should_stop_scan: Arc<Mutex<bool>>,
    scan_error: Arc<Mutex<Option<String>>>,
    scan_status: Arc<Mutex<String>>,

    // Search/filter in results
    result_search_filter: String,

    // Recovery state
    recovery_status: Arc<Mutex<String>>,
    is_recovering: Arc<Mutex<bool>>,
    recovery_progress: Arc<Mutex<String>>,
}

impl Default for RunDeleteApp {
    fn default() -> Self {
        Self {
            selected_drive: String::new(),
            folder_path: String::new(),
            filename_filter: String::new(),
            deleted_files: Arc::new(Mutex::new(Vec::new())),
            is_scanning: Arc::new(Mutex::new(false)),
            should_stop_scan: Arc::new(Mutex::new(false)),
            scan_error: Arc::new(Mutex::new(None)),
            scan_status: Arc::new(Mutex::new(String::new())),
            result_search_filter: String::new(),
            recovery_status: Arc::new(Mutex::new(String::new())),
            is_recovering: Arc::new(Mutex::new(false)),
            recovery_progress: Arc::new(Mutex::new(String::new())),
        }
    }
}

// Helper function to create a text edit with always-visible border
fn always_bordered_text_edit(ui: &mut egui::Ui, text: &mut String, width: f32) {
    egui::Frame::none()
        .stroke(egui::Stroke::new(1.0, egui::Color32::LIGHT_GRAY))
        .inner_margin(egui::Margin::same(4.0))
        .show(ui, |ui| {
            ui.add_sized(
                egui::Vec2::new(width, 20.0),
                egui::TextEdit::singleline(text),
            );
        });
}

impl RunDeleteApp {
    fn start_scan(&mut self) {
        let drive_str = self.selected_drive.trim();
        if drive_str.is_empty() {
            *self.scan_error.lock().unwrap() = Some("Please enter a drive letter".to_string());
            return;
        }

        let drive_char = drive_str.chars().next().unwrap().to_uppercase().next().unwrap();

        // Clear previous results
        self.deleted_files.lock().unwrap().clear();
        *self.scan_error.lock().unwrap() = None;
        *self.is_scanning.lock().unwrap() = true;
        *self.should_stop_scan.lock().unwrap() = false;
        *self.scan_status.lock().unwrap() = "Scanning...".to_string();

        let deleted_files = Arc::clone(&self.deleted_files);
        let is_scanning = Arc::clone(&self.is_scanning);
        let should_stop_scan = Arc::clone(&self.should_stop_scan);
        let scan_error = Arc::clone(&self.scan_error);
        let scan_status = Arc::clone(&self.scan_status);

        let folder_path = if self.folder_path.is_empty() {
            None
        } else {
            Some(self.folder_path.clone())
        };

        let filename_filter = if self.filename_filter.is_empty() {
            None
        } else {
            Some(self.filename_filter.clone())
        };

        // Spawn scanning thread
        thread::spawn(move || {
            *scan_status.lock().unwrap() = format!("Detecting filesystem type on drive {}...", drive_char);

            let result = perform_scan(
                drive_char,
                folder_path.as_deref(),
                filename_filter.as_deref(),
                &scan_status,
                &deleted_files,
                &should_stop_scan,
            );

            match result {
                Ok(was_stopped) => {
                    let count = deleted_files.lock().unwrap().len();
                    if was_stopped {
                        *scan_status.lock().unwrap() = format!("Scan stopped! Found {} deleted file(s) before stopping", count);
                    } else {
                        *scan_status.lock().unwrap() = format!("Scan complete! Found {} deleted file(s)", count);
                    }
                }
                Err(e) => {
                    *scan_error.lock().unwrap() = Some(format!("Scan error: {}", e));
                    *scan_status.lock().unwrap() = "Scan failed".to_string();
                }
            }

            *is_scanning.lock().unwrap() = false;
        });
    }

    fn stop_scan(&mut self) {
        *self.should_stop_scan.lock().unwrap() = true;
    }

    fn recover_file(&mut self, file: &DeletedFile, _index: usize) {
        let drive_str = self.selected_drive.trim();
        if drive_str.is_empty() {
            *self.recovery_status.lock().unwrap() = "Error: No source drive selected".to_string();
            return;
        }

        // Check if already recovering
        if *self.is_recovering.lock().unwrap() {
            *self.recovery_status.lock().unwrap() = "Recovery already in progress...".to_string();
            return;
        }

        let source_drive = drive_str.chars().next().unwrap().to_uppercase().next().unwrap();

        // Open file dialog
        let file_dialog = rfd::FileDialog::new()
            .set_file_name(&file.name)
            .set_title("Save recovered file");

        if let Some(path) = file_dialog.save_file() {
            // Validate drive
            let dest_path_str = path.to_string_lossy().to_string();
            if let Some(dest_drive) = dest_path_str.chars().next() {
                if dest_drive.to_uppercase().next().unwrap() == source_drive {
                    *self.recovery_status.lock().unwrap() = format!(
                        "Error: Destination must be on a different drive than {}:",
                        source_drive
                    );
                    return;
                }
            }

            // Mark as recovering
            *self.is_recovering.lock().unwrap() = true;
            *self.recovery_progress.lock().unwrap() = "Starting recovery...".to_string();
            *self.recovery_status.lock().unwrap() = String::new();

            let file_clone = file.clone();
            let recovery_status = Arc::clone(&self.recovery_status);
            let is_recovering = Arc::clone(&self.is_recovering);
            let recovery_progress = Arc::clone(&self.recovery_progress);

            // Spawn recovery thread
            thread::spawn(move || {
                // Perform recovery
                let recovery = FileRecovery::new(source_drive);

                // Update progress
                *recovery_progress.lock().unwrap() = format!("Recovering {} ({:.2} MB)...", file_clone.name, file_clone.size as f64 / 1_000_000.0);

                match recovery.recover_file(&file_clone, &path, recovery_progress.clone()) {
                    Ok(_) => {
                        *recovery_status.lock().unwrap() = format!("Successfully recovered to: {}", path.display());
                        *recovery_progress.lock().unwrap() = "Recovery complete!".to_string();
                    }
                    Err(e) => {
                        *recovery_status.lock().unwrap() = format!("Recovery failed: {}\n\nCheck recovery_debug.log on Desktop for details", e);
                        *recovery_progress.lock().unwrap() = "Recovery failed".to_string();
                    }
                }

                *is_recovering.lock().unwrap() = false;
            });
        }
    }
}

impl eframe::App for RunDeleteApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Set background color
        let mut style = (*ctx.style()).clone();
        style.visuals.window_fill = egui::Color32::from_rgb(247, 247, 250); // BACKGROUND_COLOR
        style.visuals.panel_fill = egui::Color32::from_rgb(247, 247, 250);
        ctx.set_style(style);

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(247, 247, 250)))
            .show(ctx, |ui| {
            // Blue header section (full window width, no horizontal margins)
            ui.horizontal(|ui| {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(51, 128, 230)) // PRIMARY_COLOR
                    .inner_margin(egui::Margin {
                        left: 12.0,
                        right: 12.0,
                        top: 14.0,
                        bottom: 14.0,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new("Rust Undelete - File Recovery Tool")
                                    .size(16.0)
                                    .color(egui::Color32::WHITE)
                                    .strong()
                            );
                            ui.label(
                                egui::RichText::new("Recover deleted files from NTFS and exFAT drives")
                                    .size(11.0)
                                    .color(egui::Color32::from_rgba_premultiplied(255, 255, 255, 204))
                            );
                        });
                    });
            });

            // Add vertical spacing between sections
            ui.add_space(12.0);

            // Add horizontal margins using Frame
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(12.0, 0.0))
                .show(ui, |ui| {

            // Scan Settings Card
            egui::Frame::none()
                .fill(egui::Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 20)))
                .rounding(12.0)
                .inner_margin(14.0)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        egui::RichText::new("Scan Settings")
                            .size(14.0)
                            .strong()
                            .color(egui::Color32::from_rgb(51, 51, 77))
                    );
                    ui.add_space(10.0);

                    egui::Grid::new("scan_settings_grid")
                        .num_columns(3)
                        .spacing([10.0, 6.0])
                        .show(ui, |ui| {
                            // Row 1: Drive Letter
                            ui.add_sized([120.0, 20.0], egui::Label::new(egui::RichText::new("Drive Letter:").size(13.0)));
                            always_bordered_text_edit(ui, &mut self.selected_drive, 250.0);
                            ui.label(egui::RichText::new("(e.g., D, E)").size(11.0).color(egui::Color32::from_rgb(153, 153, 179)));
                            ui.end_row();

                            // Row 2: Folder Path
                            ui.add_sized([120.0, 20.0], egui::Label::new(egui::RichText::new("Folder Path:").size(13.0)));
                            always_bordered_text_edit(ui, &mut self.folder_path, 250.0);
                            ui.label(egui::RichText::new("(optional, e.g.: Users\\John\\Documents)").size(11.0).color(egui::Color32::from_rgb(153, 153, 179)));
                            ui.end_row();

                            // Row 3: Filename Filter
                            ui.add_sized([120.0, 20.0], egui::Label::new(egui::RichText::new("Filename Filter:").size(13.0)));
                            always_bordered_text_edit(ui, &mut self.filename_filter, 250.0);
                            ui.label(egui::RichText::new("(optional, e.g.: .mkv .mp4)").size(11.0).color(egui::Color32::from_rgb(153, 153, 179)));
                            ui.end_row();
                        });

                    ui.add_space(10.0);

                    let is_scanning = *self.is_scanning.lock().unwrap();

                    ui.horizontal(|ui| {
                        let scan_button = egui::Button::new(
                            egui::RichText::new(if is_scanning { "Scanning..." } else { "🔍 Scan for Deleted Files" })
                                .size(13.0)
                                .color(egui::Color32::WHITE)
                        )
                        .fill(egui::Color32::from_rgb(51, 128, 230))
                        .min_size(egui::vec2(200.0, 30.0));

                        if ui.add_enabled(!is_scanning, scan_button).clicked() {
                            self.start_scan();
                        }

                        // Add Stop button when scanning
                        if is_scanning {
                            ui.add_space(10.0);
                            let stop_button = egui::Button::new(
                                egui::RichText::new("⏹ Stop Scan")
                                    .size(13.0)
                                    .color(egui::Color32::WHITE)
                            )
                            .fill(egui::Color32::from_rgb(230, 51, 51))
                            .min_size(egui::vec2(120.0, 30.0));

                            if ui.add(stop_button).clicked() {
                                self.stop_scan();
                            }
                        }
                    });
                });

            ui.add_space(10.0);

            // Scan Status/Progress Card
            let scan_status = self.scan_status.lock().unwrap().clone();
            let is_scanning = *self.is_scanning.lock().unwrap();

            if is_scanning || !scan_status.is_empty() {
                egui::Frame::none()
                    .fill(egui::Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 20)))
                    .rounding(12.0)
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if is_scanning {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    egui::RichText::new(&scan_status)
                                        .size(13.0)
                                        .color(egui::Color32::from_rgb(51, 128, 230))
                                );
                            });
                        } else if !scan_status.is_empty() {
                            ui.label(
                                egui::RichText::new(&scan_status)
                                    .size(13.0)
                                    .color(egui::Color32::from_rgb(51, 179, 77))
                            );
                        }
                    });
                ui.add_space(10.0);
            }

            if let Some(error) = self.scan_error.lock().unwrap().as_ref() {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(254, 242, 242))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(230, 51, 51)))
                    .rounding(12.0)
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(error)
                                .size(13.0)
                                .color(egui::Color32::from_rgb(230, 51, 51))
                        );
                    });
                ui.add_space(10.0);
            }

            // Show recovery status and progress
            let recovery_status = self.recovery_status.lock().unwrap().clone();
            let is_recovering = *self.is_recovering.lock().unwrap();
            let recovery_progress = self.recovery_progress.lock().unwrap().clone();

            if !recovery_status.is_empty() {
                let (bg_color, border_color, text_color) = if recovery_status.starts_with("Error") {
                    (egui::Color32::from_rgb(254, 242, 242), egui::Color32::from_rgb(230, 51, 51), egui::Color32::from_rgb(230, 51, 51))
                } else {
                    (egui::Color32::from_rgb(240, 253, 244), egui::Color32::from_rgb(51, 179, 77), egui::Color32::from_rgb(51, 179, 77))
                };

                egui::Frame::none()
                    .fill(bg_color)
                    .stroke(egui::Stroke::new(1.0, border_color))
                    .rounding(12.0)
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(&recovery_status)
                                .size(13.0)
                                .color(text_color)
                        );
                    });
                ui.add_space(10.0);
            }

            // Show recovery progress if recovering
            if is_recovering {
                egui::Frame::none()
                    .fill(egui::Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 20)))
                    .rounding(12.0)
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new("Recovery in Progress")
                                .size(14.0)
                                .strong()
                                .color(egui::Color32::from_rgb(51, 51, 77))
                        );
                        ui.add_space(8.0);

                        if !recovery_progress.is_empty() {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    egui::RichText::new(&recovery_progress)
                                        .size(13.0)
                                        .color(egui::Color32::from_rgb(51, 128, 230))
                                );
                            });
                        }

                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("This may take a while for large files or when file carving is needed.")
                                .size(12.0)
                                .color(egui::Color32::from_rgb(153, 153, 179))
                        );
                        ui.label(
                            egui::RichText::new("Check recovery_debug.log on your Desktop for detailed progress.")
                                .size(12.0)
                                .color(egui::Color32::from_rgb(153, 153, 179))
                        );
                    });
                ui.add_space(10.0);
            }

            // Results section
            let files = self.deleted_files.lock().unwrap();

            if files.is_empty() && !is_scanning {
                egui::Frame::none()
                    .fill(egui::Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 20)))
                    .rounding(12.0)
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new("Deleted Files")
                                .size(14.0)
                                .strong()
                                .color(egui::Color32::from_rgb(51, 51, 77))
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("No deleted files found. Click 'Scan' to search.")
                                .size(13.0)
                                .color(egui::Color32::from_rgb(153, 153, 179))
                        );
                    });
            } else if !files.is_empty() {
                // Clone files to avoid borrow checker issues
                let files_clone: Vec<DeletedFile> = files.clone();
                drop(files); // Release the lock

                egui::Frame::none()
                    .fill(egui::Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 20)))
                    .rounding(12.0)
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(format!("Deleted Files ({} found)", files_clone.len()))
                                .size(14.0)
                                .strong()
                                .color(egui::Color32::from_rgb(51, 51, 77))
                        );
                        ui.add_space(10.0);

                        // Search/Filter textbox
                        ui.horizontal(|ui| {
                            egui::Grid::new("scan_settings_grid")
                                .num_columns(3)
                                .spacing([10.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("🔍 Search:").size(13.0).color(egui::Color32::from_rgb(102, 102, 128)));
                                    always_bordered_text_edit(ui, &mut self.result_search_filter, 400.0);
                                });
                            if !self.result_search_filter.is_empty() {
                                ui.add_space(5.0);
                                ui.label(egui::RichText::new(format!("(filtering by: \"{}\")", self.result_search_filter))
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(153, 153, 179)));
                            }
                        });
                        ui.add_space(10.0);

                        // Filter files based on search input
                        let filtered_files: Vec<_> = if self.result_search_filter.is_empty() {
                            files_clone.iter().enumerate().collect()
                        } else {
                            let search_lower = self.result_search_filter.to_lowercase();
                            files_clone.iter().enumerate()
                                .filter(|(_, file)| {
                                    file.name.to_lowercase().contains(&search_lower) ||
                                    file.path.to_lowercase().contains(&search_lower)
                                })
                                .collect()
                        };

                        // Show filtered count if filtering
                        if !self.result_search_filter.is_empty() && filtered_files.len() != files_clone.len() {
                            ui.label(
                                egui::RichText::new(format!("Showing {} of {} files", filtered_files.len(), files_clone.len()))
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(51, 128, 230))
                            );
                            ui.add_space(5.0);
                        }

                        egui::ScrollArea::both()
                            .max_height(400.0)
                            .show(ui, |ui| {
                                for (index, file) in filtered_files.iter() {
                                    // Alternating row colors
                                    let bg_color = if index % 2 == 0 {
                                        egui::Color32::WHITE
                                    } else {
                                        egui::Color32::from_rgb(250, 250, 252)
                                    };

                                    egui::Frame::none()
                                        .fill(bg_color)
                                        .inner_margin(egui::Margin::symmetric(8.0, 10.0))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.vertical(|ui| {
                                                    ui.label(
                                                        egui::RichText::new(&file.name)
                                                            .size(13.0)
                                                            .strong()
                                                            .color(egui::Color32::from_rgb(51, 51, 77))
                                                    );
                                                    ui.label(
                                                        egui::RichText::new(format!("Path: {}", file.path))
                                                            .size(12.0)
                                                            .color(egui::Color32::from_rgb(102, 102, 128))
                                                    );

                                                    let size_str = if file.size > 1_000_000_000 {
                                                        format!("{:.2} GB", file.size as f64 / 1_000_000_000.0)
                                                    } else if file.size > 1_000_000 {
                                                        format!("{:.2} MB", file.size as f64 / 1_000_000.0)
                                                    } else if file.size > 1_000 {
                                                        format!("{:.2} KB", file.size as f64 / 1_000.0)
                                                    } else {
                                                        format!("{} bytes", file.size)
                                                    };

                                                    ui.label(
                                                        egui::RichText::new(format!("Size: {}", size_str))
                                                            .size(12.0)
                                                            .color(egui::Color32::from_rgb(102, 102, 128))
                                                    );

                                                    if !file.is_recoverable {
                                                        ui.label(
                                                            egui::RichText::new("⚠ May not be fully recoverable")
                                                                .size(11.0)
                                                                .color(egui::Color32::from_rgb(230, 153, 0))
                                                        );
                                                    }
                                                });

                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    let recover_button = egui::Button::new(
                                                        egui::RichText::new("💾 Recover")
                                                            .size(12.0)
                                                            .color(egui::Color32::WHITE)
                                                    )
                                                    .fill(egui::Color32::from_rgb(51, 128, 230))
                                                    .min_size(egui::vec2(90.0, 28.0));

                                                    if ui.add(recover_button).clicked() {
                                                        self.recover_file(file, *index);
                                                    }
                                                });
                                            });
                                        });
                                }
                            });
                    });
            }
                }); // Close margin Frame
        }); // Close egui::CentralPanel

        // Request repaint if scanning or recovering
        if *self.is_scanning.lock().unwrap() || *self.is_recovering.lock().unwrap() {
            ctx.request_repaint();
        }
    }
}

fn perform_scan(
    drive: char,
    folder_path: Option<&str>,
    filename_filter: Option<&str>,
    scan_status: &Arc<Mutex<String>>,
    deleted_files: &Arc<Mutex<Vec<DeletedFile>>>,
    should_stop: &Arc<Mutex<bool>>,
) -> anyhow::Result<bool> {
    // Create initial log file to verify we can write to Desktop
    use std::fs::OpenOptions;
    use std::io::Write;

    let log_path = std::env::var("USERPROFILE")
        .map(|base| format!("{}\\Desktop\\rsundelete_debug.log", base))
        .unwrap_or_else(|_| "C:\\rsundelete_debug.log".to_string());

    let mut early_log = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path);

    match &mut early_log {
        Ok(log) => {
            let _ = writeln!(log, "=== Rust Undelete Early Debug Log ===");
            let _ = writeln!(log, "Log created successfully at: {}", log_path);
            let _ = writeln!(log, "Drive requested: {}", drive);
            let _ = writeln!(log, "Detecting filesystem type...");
            let _ = log.flush();
        }
        Err(e) => {
            // Can't write to Desktop, try C drive
            let fallback_path = "C:\\rsundelete_debug.log";
            if let Ok(mut fallback_log) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(fallback_path)
            {
                let _ = writeln!(fallback_log, "=== Rust Undelete Early Debug Log ===");
                let _ = writeln!(fallback_log, "Could not write to Desktop: {}", e);
                let _ = writeln!(fallback_log, "Writing to: {}", fallback_path);
                let _ = writeln!(fallback_log, "Drive requested: {}", drive);
                let _ = fallback_log.flush();
            }
        }
    }

    // Determine filesystem type
    let fs_type = match disk_access::get_filesystem_type(drive) {
        Ok(ft) => {
            if let Ok(ref mut log) = early_log {
                let _ = writeln!(log, "Filesystem type detected: {:?}", ft);
                let _ = log.flush();
            }
            ft
        }
        Err(e) => {
            if let Ok(ref mut log) = early_log {
                let _ = writeln!(log, "FAILED to detect filesystem: {}", e);
                let _ = log.flush();
            }
            return Err(e);
        }
    };

    *scan_status.lock().unwrap() = format!("Scanning {} drive for deleted files...",
        match fs_type {
            disk_access::FileSystemType::NTFS => "NTFS",
            disk_access::FileSystemType::ExFAT => "exFAT",
            _ => "Unknown",
        }
    );

    if let Ok(ref mut log) = early_log {
        let _ = writeln!(log, "Calling scanner for {:?}", fs_type);
        let _ = log.flush();
    }

    let was_stopped = match fs_type {
        disk_access::FileSystemType::NTFS => {
            let mut scanner = NtfsScanner::new(drive);
            scanner.scan_realtime(drive, folder_path, filename_filter, deleted_files, should_stop)?
        }
        disk_access::FileSystemType::ExFAT => {
            let mut scanner = ExfatScanner::new(drive);
            scanner.scan_realtime(drive, folder_path, filename_filter, deleted_files, should_stop)?
        }
        _ => {
            anyhow::bail!("Unsupported filesystem type. Only NTFS and exFAT are supported.");
        }
    };

    // Sort by name (lock the mutex to sort)
    deleted_files.lock().unwrap().sort_by(|a, b| a.name.cmp(&b.name));

    Ok(was_stopped)
}
