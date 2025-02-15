import customtkinter as ctk
from tkinter import filedialog
import threading

from PIL import Image

from hashes import generate_apk_hash, extract_metadata
from VirusTotal import VirusTotalClient
from log import log_setup

logger = log_setup()

class AppDetectorGUI:
    def __init__(self):
        self.app = ctk.CTk()
        self.vt_client = VirusTotalClient()
        self.selected_file_path = None
        self._setup_gui()
        
    def _setup_gui(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.app.title("Clone and Fake App Detection")
        self.app.geometry("700x700")

        self.main_frame = ctk.CTkFrame(self.app, fg_color="#050d17")
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.header_label = ctk.CTkLabel(
            self.main_frame, 
            text="Clone & Fake App Detection", 
            font=("Arial", 20, "bold")
        )
        self.header_label.pack(pady=10)

        try:
            self.bg_image = ctk.CTkImage(
                light_image=Image.open("lock_img.jpeg"), 
                dark_image=Image.open("lock_img.jpeg"),
                size=(650, 300)
            )
            self.bg_label = ctk.CTkLabel(self.main_frame, text="", image=self.bg_image)
            self.bg_label.pack()
        except Exception as e:
            logger.warning(f"Could not load image: {e}")

        self.info_label = ctk.CTkLabel(
            self.main_frame, 
            text="1. Click 'Browse APK' to select an APK.\n"
                 "2. Click 'Start Scan' to analyze the file.\n"
                 "3. View the report below for any fake/clone indicators."
        )
        self.info_label.pack(pady=5)

        self.file_path_entry = ctk.CTkEntry(
            self.main_frame, 
            placeholder_text="File path will appear here...",
            width=400
        )
        self.file_path_entry.pack(pady=5)

        self.browse_btn = ctk.CTkButton(
            self.main_frame,
            text="Browse APK",
            command=self._browse_apk,
            width=200,
            height=40
        )
        self.browse_btn.pack(pady=5)

        self.scan_btn = ctk.CTkButton(
            self.main_frame,
            text="Start Scan",
            command=self._start_analysis_thread,
            width=200,
            height=40,
            state="disabled"
        )
        self.scan_btn.pack(pady=5)
        
        self.progress = ctk.CTkProgressBar(self.main_frame, mode="indeterminate")
        self.progress.pack(pady=10)

        self.result_text = ctk.CTkTextbox(
            self.main_frame,
            width=600,
            height=300,
            wrap="word"
        )
        self.result_text.pack(pady=10)

    def _browse_apk(self):
        file_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
        if file_path:
            self.selected_file_path = file_path
            self.file_path_entry.delete(0, "end")
            self.file_path_entry.insert(0, file_path)
            
            self.scan_btn.configure(state="normal")

    def _start_analysis_thread(self):
        thread = threading.Thread(target=self._analyze_apk)
        thread.start()

    def _analyze_apk(self):
        try:
            self._toggle_ui_state(disabled=True)
            if not self.selected_file_path:
                self._update_result("Error: No file selected.", is_error=True)
                return

            # 1. Generate Hash
            self._update_result("⏳ Generating hash...")
            apk_hash = generate_apk_hash(self.selected_file_path)

            # 2. Extract Metadata
            self._update_result("⏳ Extracting metadata...")
            metadata = extract_metadata(self.selected_file_path)

            # 3. VirusTotal Check
            self._update_result("Querying VirusTotal...")
            vt_report = self.vt_client.check_hash(apk_hash)
            
            # 4. Check for Fake/Clone Indicators
            self._update_result("Analyzing for fake/clone indicators...")
            fake_indicators = self._check_fake_indicators(metadata)

            # Display Results
            report = self._format_report(apk_hash, metadata, vt_report, fake_indicators)
            self._update_result(report)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self._update_result(f"Error: {str(e)}", is_error=True)
        finally:
            self._toggle_ui_state(disabled=False)

    def _check_fake_indicators(self, metadata: dict) -> list:
        indicators = []
        permissions = metadata.get('permissions', [])
        if "android.permission.SEND_SMS" in permissions:
            indicators.append("Suspicious permission: SEND_SMS")
        if not metadata.get('certificates'):
            indicators.append("No valid certificates found")
        return indicators

    def _toggle_ui_state(self, disabled: bool):
        state = "disabled" if disabled else "normal"
        self.browse_btn.configure(state=state)
        self.scan_btn.configure(state=state)

        if disabled:
            self.progress.start()
        else:
            self.progress.stop()
    
    def _update_result(self, text: str, is_error: bool = False):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("end", text + "\n")
        self.result_text.configure(state="disabled")

    def _format_report(self, apk_hash: str, metadata: dict, vt_report: dict, fake_indicators: list) -> str:
        report = []
        report.append(f"🔑 SHA-256 Hash: {apk_hash}")
        
        if metadata:
            report.append(f"\n=> Package Name: {metadata.get('package_name', 'N/A')}")
            report.append(f"=> Version: {metadata.get('version', 'N/A')}")
            report.append(f"=> Permissions: {len(metadata.get('permissions', []))}")
        
        if vt_report.get('data'):
            attributes = vt_report['data'].get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            report.append("\n----- VirusTotal Report:")
            report.append(f"   Clean: {stats.get('harmless', 0)}")
            report.append(f"   Suspicious: {stats.get('suspicious', 0)}")
            report.append(f"   Malicious: {stats.get('malicious', 0)}")
        else:
            report.append("\n No VirusTotal data found")
            
        if fake_indicators:
            report.append("\nFake/Clone Indicators:")
            report.extend(fake_indicators)

        return "\n".join(report)

    def run(self):
        self.app.mainloop()

# import customtkinter as ctk
# from tkinter import filedialog
# from hashes import *
# from VirusTotal import VirusTotalClient
# from log import log_setup
# import threading

# logger = log_setup()

# class AppDetectorGUI:
#     def __init__(self):
#         self.app = ctk.CTk()
#         self.vt_client = VirusTotalClient()
#         self._setup_gui()
        
#     def _setup_gui(self):
#         ctk.set_appearance_mode("dark")
#         ctk.set_default_color_theme("blue")
#         self.app.title("Clone and Fake App Detection and Mitigation")
#         self.app.geometry("700x600")
        
#         self.main_frame = ctk.CTkFrame(self.app)
#         self.main_frame.pack(pady = 20, padx=20, fill="both", expand=True)
        
#         self.upload_btn = ctk.CTkButton(
#             self.main_frame,
#             text="Upload APK",
#             command=self._start_analysis_thread,
#             width=200,
#             height=40
#         )
#         self.upload_btn.pack(pady=15)
        
#         # Progress Bar
#         self.progress = ctk.CTkProgressBar(self.main_frame, mode="indeterminate")
#         self.progress.pack(pady=10)

#         # Result Display
#         self.result_text = ctk.CTkTextbox(
#             self.main_frame,
#             width=600,
#             height=300,
#             wrap="word"
#         )
#         self.result_text.pack(pady=10)
        
#     def _start_analysis_thread(self):
#         # Run analysis in background to prevent UI freeze.
#         thread = threading.Thread(target=self._analyze_apk)
#         thread.start()
            
#     def _analyze_apk(self):
#         #"""Handle APK analysis workflow."""
#         try:
#             self._toggle_ui_state(disabled=True)
#             file_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk")])
#             if not file_path:
#                 return

#             # Step 1: Generate Hash
#             self._update_result("⏳ Generating hash...")
#             apk_hash = generate_apk_hash(file_path)

#             # Step 2: Extract Metadata
#             self._update_result("⏳ Extracting metadata...")
#             metadata = extract_metadata(file_path)

#             # Step 3: VirusTotal Check
#             self._update_result("🔍 Querying VirusTotal...")
#             vt_report = self.vt_client.check_hash(apk_hash)
            
#             # Step 4: Check for Fake/Clone Indicators
#             self._update_result("🔎 Analyzing for fake/clone indicators...")
#             fake_indicators = self._check_fake_indicators(metadata)

#             # Display Results
#             report = self._format_report(apk_hash, metadata, vt_report, fake_indicators)
#             self._update_result(report)

#         except Exception as e:
#             logger.error(f"Analysis failed: {e}")
#             self._update_result(f"❌ Error: {str(e)}", is_error=True)
#         finally:
#             self._toggle_ui_state(disabled=False)
                
#     def _check_fake_indicators(self, metadata: dict) -> list:
#     #"""Check for signs of fake/clone apps."""
#         indicators = []
#         if "android.permission.SEND_SMS" in metadata.get('permissions', []):
#             indicators.append("⚠️ Suspicious permission: SEND_SMS")
#         if not metadata.get('certificates'):
#             indicators.append("⚠️ No valid certificates found")
#         return indicators

#     def _toggle_ui_state(self, disabled: bool):
#         """Enable/disable UI elements during processing."""
#         state = "disabled" if disabled else "normal"
#         self.upload_btn.configure(state=state)
#         if disabled:
#             self.progress.start()
#         else:
#             self.progress.stop()
        
    
#     def _update_result(self, text: str, is_error: bool = False):
#         """Update result textbox with formatted message."""
#         self.result_text.configure(state="normal")
#         self.result_text.delete("1.0", "end")
#         self.result_text.insert("end", text + "\n")
#         self.result_text.configure(state="disabled")

#     def _format_report(self, apk_hash: str, metadata: dict, vt_report: dict, fake_indicators: list) -> str:
#         """Format analysis results for display."""
#         report = []
#         report.append(f"🔑 SHA-256 Hash: {apk_hash}")
        
#         if metadata:
#             report.append(f"\n📦 Package Name: {metadata.get('package_name', 'N/A')}")
#             report.append(f"📱 Version: {metadata.get('version', 'N/A')}")
#             report.append(f"🔐 Permissions: {len(metadata.get('permissions', []))}")
        
#         if vt_report.get('data'):
#             attributes = vt_report['data'].get('attributes', {})
#             stats = attributes.get('last_analysis_stats', {})

#             report.append("\n🛡️ VirusTotal Report:")
#             report.append(f"  ✅ Clean: {stats.get('harmless', 0)}")
#             report.append(f"  ⚠️ Suspicious: {stats.get('suspicious', 0)}")
#             report.append(f"  ❌ Malicious: {stats.get('malicious', 0)}")
#         else:
#             report.append("\n⚠️ No VirusTotal data found.")

#         # if vt_report.get('data'):
#         #     stats = vt_report['data']['attributes']['last_analysis_stats']
#         #     report.append("\n🛡️ VirusTotal Report:")
#         #     report.append(f"  ✅ Clean: {stats['harmless']}")
#         #     report.append(f"  ⚠️ Suspicious: {stats['suspicious']}")
#         #     report.append(f"  ❌ Malicious: {stats['malicious']}")
#         # else:
#         #     report.append("\n⚠️ No VirusTotal data found")
#         if fake_indicators:
#             report.append("\n🚨 Fake/Clone Indicators:")
#             report.extend(fake_indicators)

#         return "\n".join(report)

#     def run(self):
#         self.app.mainloop()
        
# # import customtkinter as ctk

# # root = ctk.CTk()
# # root.title("Clone and Fake App Detection.")
# # root.geometry("500x600")

# # main_frame = ctk.CTkFrame(root, fg_color="#291f33", corner_radius=10)
# # main_frame.pack(expand=True, fill="both", padx=10, pady=10)

# # main_label = ctk.CTkLabel(main_frame, text="Clone and Fake App Detector",font=("Segoe UI", 22, "bold"), text_color="white")
# # main_label.pack(pady=20)

# # button_styles = {
# #     "Select APK":"#290c87",
# #     "Start app SCAN":"#410c87"
# # }

# # select_apk_button = ctk.CTkButton(main_frame, text="Select APK", fg_color=button_styles["Select APK"], font=("Segoe UI", 12))
# # select_apk_button.pack(pady=5)

# # app_scan_button = ctk.CTkButton(main_frame, text="Start app SCAN", fg_color=button_styles["Start app SCAN"], font=("Segeo UI", 12))
# # app_scan_button.pack(pady=5)

# # scan_progress = ctk.CTkProgressBar(main_frame, orientation="horizontal", mode="indeterminate", width=300)
# # scan_progress.pack(pady=10)
# # scan_progress.set(0)

# # log_text = ctk.CTkScrollableFrame(main_frame, width=400)
# # log_text.pack(pady=10)

# # root.mainloop()