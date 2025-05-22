#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Original LCP Decryption logic adapted from https://notabug.org/uhuxybim/DeDRM_tools-LCP
# Automated download and decryption workflow by Gemini (Google AI)
# UI improvements and EXE packaging instructions by Gemini (Google AI)

"""
Automates the process of decrypting Readium LCP protected PDFs directly from a .lcpl file.
Downloads the encrypted content, packages it with the license, decrypts, and extracts the PDF.
Includes UI enhancements and instructions for EXE packaging.
"""

__license__ = 'GPL v3'
__version__ = "4.1"  # Minor version bump for UI changes

import json
import hashlib
import base64
import binascii
import os
import shutil
from zipfile import ZipFile, ZIP_DEFLATED
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.ttk import Progressbar, Label, Button, Frame  # Import Frame for better layout
import sys
import subprocess
import tempfile
import requests
import re

# --- 核心解密逻辑 (与之前版本相同) ---
try:
    from Crypto.Cipher import AES
except ImportError:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # Suppress pip output
        from Crypto.Cipher import AES
    except Exception as e:
        messagebox.showerror("安装错误", f"无法安装 'pycryptodome' 库。请手动运行 'pip install pycryptodome'。\n错误: {e}")
        sys.exit(1)

try:
    import requests
except ImportError:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"], # <-- 将单引号改为双引号
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import requests
    except Exception as e:
        messagebox.showerror("安装错误", f"无法安装 'requests' 库。请手动运行 'pip install requests'。\n错误: {e}")
        sys.exit(1)

class Decryptor(object):
    def __init__(self, bookkey):
        self.book_key = bookkey

    def decrypt(self, data):
        aes = AES.new(self.book_key, AES.MODE_CBC, data[:16])
        data = aes.decrypt(data[16:])
        return data


class LCPError(Exception):
    pass


class LCPTransform:
    @staticmethod
    def secret_transform_basic(input_hash):
        return input_hash

    @staticmethod
    def secret_transform_profile10(input_hash):
        masterkey = "b3a07c4d42880e69398e05392405050efeea0664c0b638b7c986556fa9b58d77b31a40eb6a4fdba1e4537229d9f779daad1cc41ee968153cb71f27dc9696d40f"
        masterkey = bytearray.fromhex(masterkey)

        current_hash = bytearray.fromhex(input_hash)

        for byte in masterkey:
            current_hash.append(byte)
            current_hash = bytearray(hashlib.sha256(current_hash).digest())
        return binascii.hexlify(current_hash).decode("latin-1")

    @staticmethod
    def userpass_to_hash(passphrase_bytes, algorithm):
        if (algorithm == "http://www.w3.org/2001/04/xmlenc#sha256"):
            algo = "SHA256"
            user_password_hashed = hashlib.sha256(passphrase_bytes).hexdigest()
        else:
            print(f"LCP: Book is using unsupported user key algorithm: {algorithm}")
            return None, None
        return algo, user_password_hashed


def dataDecryptLCP(b64data, hex_key):
    iv = base64.b64decode(b64data.encode('ascii'))[:16]
    cipher_data = base64.b64decode(b64data.encode('ascii'))[16:]

    aes = AES.new(binascii.unhexlify(hex_key), AES.MODE_CBC, iv)
    temp = aes.decrypt(cipher_data)

    padding = temp[-1]
    data_temp = temp[:-padding]

    return data_temp


def decryptLCPbook_core(zip_file_path, license_data, passphrases, status_callback=None, progress_callback=None):
    """
    Core decryption logic that expects a path to a ZIP file and license JSON data.
    Returns decrypted content and additional files.
    """
    if status_callback:
        status_callback("正在打开加密文件...")

    try:
        file = ZipFile(open(zip_file_path, 'rb'))
    except Exception as e:
        raise LCPError(f"无法打开临时 ZIP 文件: {e}")

    try:
        license = license_data
        if status_callback:
            status_callback(f"LCP: 找到 LCP 加密书籍 {license['id']}")
    except Exception as e:
        raise LCPError(f"处理许可证数据失败: {e}")

    profile = license["encryption"]["profile"]
    if profile == "http://readium.org/lcp/basic-profile":
        if status_callback: status_callback("LCP: 书籍使用 lcp/basic-profile 加密。")
        transform_algo = LCPTransform.secret_transform_basic
    elif profile == "http://readium.org/lcp/profile-1.0":
        if status_callback: status_callback("LCP: 书籍使用 lcp/profile-1.0 加密。")
        transform_algo = LCPTransform.secret_transform_profile10
    else:
        file.close()
        raise LCPError(f"书籍使用未知的 LCP 加密标准: {profile}")

    content_key_algo = license["encryption"]["content_key"]["algorithm"]
    if content_key_algo != "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
        file.close()
        raise LCPError(f"书籍使用未知的 LCP 加密算法: {content_key_algo}")

    key_check = license["encryption"]["user_key"]["key_check"]
    encrypted_content_key = license["encryption"]["content_key"]["encrypted_value"]

    password_hashes = []

    if "value" in license["encryption"]["user_key"]:
        try:
            password_hashes.append(
                binascii.hexlify(base64.b64decode(license["encryption"]["user_key"]["value"].encode())).decode("ascii"))
        except Exception as e:
            if status_callback: status_callback(f"警告: 无法解码 user_key 'value': {e}")
    if "hex_value" in license["encryption"]["user_key"]:
        password_hashes.append(
            binascii.hexlify(bytearray.fromhex(license["encryption"]["user_key"]["hex_value"])).decode("ascii"))

    for possible_passphrase in passphrases:
        algo = "http://www.w3.org/2001/04/xmlenc#sha256"
        if "algorithm" in license["encryption"]["user_key"]:
            algo = license["encryption"]["user_key"]["algorithm"]

        algo, tmp_pw = LCPTransform.userpass_to_hash(possible_passphrase.encode('utf-8'), algo)
        if tmp_pw is not None:
            password_hashes.append(tmp_pw)

    correct_password_hash = None

    if status_callback: status_callback("正在尝试密码...")
    for possible_hash in password_hashes:
        transformed_hash = transform_algo(possible_hash)
        try:
            decrypted = dataDecryptLCP(key_check, transformed_hash)
            if decrypted is not None and decrypted.decode("ascii", errors="ignore") == license["id"]:
                correct_password_hash = transformed_hash
                break
        except Exception:
            pass

    if correct_password_hash is None:
        file.close()
        error_msg = f"LCP: 尝试了 {len(password_hashes)} 个密码，但都无法解密书籍..."
        if ("text_hint" in license["encryption"]["user_key"] and license["encryption"]["user_key"]["text_hint"] != ""):
            error_msg += f"\nLCP: 书籍分发商给出了以下密码提示: \"{license['encryption']['user_key']['text_hint']}\""
        for link in license["links"]:
            if ("rel" in link and link["rel"] == "hint"):
                error_msg += f"\nLCP: 你可以在以下网页找到或重置 LCP 密码: {link['href']}"
                break
        raise LCPError(error_msg + "\n请在界面中输入正确的密码，然后重试。")

    if status_callback: status_callback("LCP: 找到正确的密码，正在解密书籍...")

    decrypted_content_key = dataDecryptLCP(encrypted_content_key, correct_password_hash)

    if decrypted_content_key is None:
        raise LCPError("解密后的内容密钥为空")

    decryptor = Decryptor(decrypted_content_key)

    try:
        manifest = json.loads(file.read('manifest.json'))
        hrefs = [entry["href"] for entry in manifest["readingOrder"]]
    except KeyError:
        raise LCPError("ZIP 文件中缺少 'manifest.json' 文件或其格式不正确。")
    except json.JSONDecodeError:
        raise LCPError("'manifest.json' 文件损坏或格式不正确。")

    decrypted_files_data = {}
    total_files_to_decrypt = len(hrefs)
    current_progress = 0

    if status_callback: status_callback(f"找到 {total_files_to_decrypt} 个需要解密的文件...")

    for i, file_href in enumerate(hrefs):
        try:
            encrypted_data = file.read(file_href)
            decrypted_data = decryptor.decrypt(encrypted_data)
            decrypted_files_data[file_href] = decrypted_data

            if status_callback:
                status_callback(f"LCP: 文件 '{file_href}' 成功解密。")
            current_progress = int((i + 1) / total_files_to_decrypt * 90)
            if progress_callback:
                progress_callback(current_progress)

        except KeyError:
            if status_callback: status_callback(f"警告: 文件 '{file_href}' 未在压缩包中找到，跳过。")
        except Exception as e:
            if status_callback: status_callback(f"错误: 解密文件 '{file_href}' 失败: {e}")

    additional_files_data = {}
    for zipped_file in file.namelist():
        if zipped_file not in hrefs and zipped_file != 'license.lcpl' and zipped_file != 'manifest.json' and not zipped_file.endswith(
                '/'):
            try:
                additional_files_data[zipped_file] = file.read(zipped_file)
                if status_callback: status_callback(f"复制非加密文件: {zipped_file}")
            except Exception as e:
                if status_callback: status_callback(f"警告: 复制非加密文件 '{zipped_file}' 失败: {e}")

    file.close()
    if status_callback: status_callback("所有加密和非加密文件已处理。")
    return decrypted_files_data, additional_files_data


class App:
    def __init__(self, master):
        self.master = master
        master.title("LCP PDF 一键解密工具")
        master.geometry("500x350")
        master.resizable(False, False)

        self.path_lcpl = None
        self.passphrase_file = "passphrase.txt"

        # --- UI 框架和布局 ---
        main_frame = Frame(master, padding="15 15 15 15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # File Selection Section
        file_selection_frame = Frame(main_frame, padding="5 5 5 5", relief=tk.GROOVE, borderwidth=1)
        file_selection_frame.pack(fill=tk.X, pady=10)

        Label(file_selection_frame, text="1. 选择您下载的 *.lcpl 文件:", font=("Segoe UI", 10, "bold")).pack(pady=5,
                                                                                                     anchor=tk.W)

        self.lcpl_path_display = Label(file_selection_frame, text="未选择 .lcpl 文件", wraplength=350, foreground="gray")
        self.lcpl_path_display.pack(pady=5, fill=tk.X, padx=5)

        Button(file_selection_frame, text="选择 .lcpl 文件", command=self.select_lcpl).pack(pady=5)

        # === 重点修改开始 ===
        # Action Button (Moved here, before status and progress)
        # 确保 self.btn_start_decrypt 在被 check_can_start() 访问之前被创建
        self.btn_start_decrypt = Button(main_frame, text="2. 一键下载、解密并提取 PDF", command=self.start_workflow,
                                        state=tk.DISABLED, style='Accent.TButton')  # Use Accent style if available
        self.btn_start_decrypt.pack(pady=20)
        # === 重点修改结束 ===

        # Status and Progress Section
        status_frame = Frame(main_frame, padding="5 5 5 5", relief=tk.GROOVE, borderwidth=1)
        status_frame.pack(fill=tk.X, pady=10)

        self.progress_label = Label(status_frame, text="状态: 等待文件选择...", wraplength=450)
        self.progress_label.pack(pady=5, fill=tk.X, padx=5, anchor=tk.W)

        self.progressbar = Progressbar(status_frame, orient="horizontal", length=300, mode="determinate")
        self.progressbar.pack(pady=10, fill=tk.X, padx=5)

        # Load saved passphrase
        self.passphrase = self.load_passphrase()
        self.check_can_start()  # 现在 self.btn_start_decrypt 已经被创建了

    def load_passphrase(self):
        if os.path.exists(self.passphrase_file):
            try:
                with open(self.passphrase_file, "r", encoding='utf-8') as f:
                    return f.read().strip()
            except Exception as e:
                messagebox.showwarning("加载密码失败", f"无法加载密码文件 '{self.passphrase_file}'。将重新提示密码。\n错误: {e}")
                return ""
        return ""

    def save_passphrase(self, passphrase):
        try:
            with open(self.passphrase_file, "w", encoding='utf-8') as f:
                f.write(passphrase)
        except Exception as e:
            messagebox.showwarning("保存密码失败", f"无法保存密码到 '{self.passphrase_file}'。请检查文件权限。\n错误: {e}")

    def update_status(self, message):
        self.progress_label.config(text=f"状态: {message}")
        self.master.update_idletasks()

    def update_progress(self, value):
        self.progressbar['value'] = value
        self.master.update_idletasks()

    def check_can_start(self):
        if self.path_lcpl:
            self.btn_start_decrypt.config(state=tk.NORMAL)
            self.update_status("已选择 .lcpl 文件，点击 '一键下载、解密并提取 PDF' 开始。")
        else:
            self.btn_start_decrypt.config(state=tk.DISABLED)
            self.update_status("请选择 .lcpl 文件。")

    def select_lcpl(self):
        file_path = filedialog.askopenfilename(
            title="选择 LCP 许可证文件 (.lcpl)",
            filetypes=[("LCP License files", "*.lcpl")]
        )
        if file_path:
            self.path_lcpl = file_path
            self.lcpl_path_display.config(text=f"已选择: {os.path.basename(file_path)}", foreground="black")
        else:
            self.path_lcpl = None
            self.lcpl_path_display.config(text="未选择 .lcpl 文件", foreground="gray")
        self.check_can_start()

    def download_and_package_content(self, lcpl_path, status_callback, progress_callback):
        status_callback("正在解析 .lcpl 文件并查找下载链接...")
        progress_callback(5)

        try:
            with open(lcpl_path, 'r', encoding='utf-8') as f:
                lcpl_data = json.load(f)
        except json.JSONDecodeError as e:
            raise LCPError(f".lcpl 文件损坏或格式不正确: {e}")
        except FileNotFoundError:
            raise LCPError(f".lcpl 文件未找到: {lcpl_path}")

        download_link = None
        for link in lcpl_data.get("links", []):
            if link.get("rel") == "publication" and "href" in link:
                download_link = link["href"]
                break

        if not download_link:
            raise LCPError("未在 .lcpl 文件中找到 'publication' 下载链接。LCP 文件可能无效或不支持。")

        status_callback(f"找到下载链接: {download_link}")
        progress_callback(10)

        book_id = lcpl_data.get("id", os.path.splitext(os.path.basename(lcpl_path))[0])
        output_folder_base_name = re.sub(r'[\\/:*?"<>|]', '', book_id)
        if not output_folder_base_name:
            output_folder_base_name = os.path.splitext(os.path.basename(lcpl_path))[0]

        output_base_dir = os.path.dirname(lcpl_path)
        final_output_folder = os.path.join(output_base_dir, output_folder_base_name + "_decrypted")

        status_callback("正在下载加密内容...")
        temp_dir_obj = tempfile.TemporaryDirectory()  # Create TemporaryDirectory here
        try:
            response = requests.get(download_link, stream=True, timeout=60)  # Increased timeout
            response.raise_for_status()

            content_disposition = response.headers.get('Content-Disposition')
            downloaded_filename = None
            if content_disposition:
                fname_match = re.search(r'filename\*?=(?:UTF-8\'\')?\"?([^\"]+)\"?', content_disposition, re.I)
                if fname_match:
                    downloaded_filename = requests.utils.unquote(fname_match.group(1))

            if not downloaded_filename:
                downloaded_filename = os.path.basename(download_link.split('?')[0])
                if not downloaded_filename or len(downloaded_filename) > 50:  # Avoid very long or empty names
                    # Try to guess from content type and book ID
                    content_type = response.headers.get('Content-Type', '')
                    ext = ".bin"
                    if 'application/pdf' in content_type:
                        ext = ".pdf"
                    elif 'application/epub+zip' in content_type:
                        ext = ".epub"
                    elif 'audio/' in content_type:  # For audiobooks
                        ext = ".zip"  # Often packaged as zip
                    downloaded_filename = output_folder_base_name + ext

            temp_download_path = os.path.join(temp_dir_obj.name, downloaded_filename)

            total_size = int(response.headers.get('content-length', 0))
            bytes_downloaded = 0

            with open(temp_download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    bytes_downloaded += len(chunk)
                    if total_size > 0:
                        progress_callback(10 + int(bytes_downloaded / total_size * 20))
                    status_callback(
                        f"下载中: {bytes_downloaded / (1024 * 1024):.2f}MB / {total_size / (1024 * 1024):.2f}MB")

            status_callback("下载完成。")
            progress_callback(30)

            is_zip = False
            try:
                with ZipFile(temp_download_path, 'r') as test_zip:
                    _ = test_zip.namelist()
                is_zip = True
            except Exception:
                is_zip = False

            temp_book_zip_path = None
            if is_zip:
                status_callback("下载的内容已是 ZIP 文件，正在添加许可证...")
                temp_book_zip_path = os.path.join(temp_dir_obj.name, "lcp_book_with_license.zip")
                shutil.copyfile(temp_download_path, temp_book_zip_path)
                with ZipFile(temp_book_zip_path, 'a', compression=ZIP_DEFLATED) as zipf:
                    zipf.write(lcpl_path, arcname="license.lcpl")
            else:
                status_callback("下载的内容不是 ZIP 文件，正在创建 LCP ZIP 包...")
                temp_book_zip_path = os.path.join(temp_dir_obj.name, "lcp_book_package.zip")

                original_content_name = os.path.basename(downloaded_filename)
                if not os.path.splitext(original_content_name)[1]:
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/pdf' in content_type:
                        original_content_name += '.pdf'
                    elif 'application/epub+zip' in content_type:
                        original_content_name += '.epub'
                    elif 'audio/' in content_type:
                        original_content_name += '.mp3'  # Common for single audio tracks

                manifest_data = {
                    "metadata": {
                        "title": lcpl_data.get("title", lcpl_data.get("id", "Decrypted Book")),
                        "identifier": lcpl_data.get("id", "urn:uuid:unknown"),
                        "type": "https://schema.org/CreativeWork",
                        "conformsTo": "https://readium.org/webpub-manifest/context.jsonld",
                        "readingProgression": "ltr"
                    },
                    "readingOrder": [
                        {"href": original_content_name,
                         "type": response.headers.get('Content-Type', 'application/octet-stream')}
                    ]
                }
                manifest_json_bytes = json.dumps(manifest_data, indent=2).encode('utf-8')

                with ZipFile(temp_book_zip_path, 'w', compression=ZIP_DEFLATED) as zipf:
                    # Write lcpl_data as bytes
                    zipf.writestr("license.lcpl", json.dumps(lcpl_data).encode('utf-8'))
                    zipf.writestr("manifest.json", manifest_json_bytes)
                    zipf.write(temp_download_path, arcname=original_content_name)

                status_callback("LCP ZIP 包创建成功。")

            progress_callback(40)
            return temp_book_zip_path, lcpl_data, final_output_folder, temp_dir_obj

        except requests.exceptions.RequestException as e:
            raise LCPError(f"下载文件失败 (网络错误): {e}")
        except Exception as e:
            raise LCPError(f"文件处理或打包失败: {e}")
        finally:
            # temp_dir_obj will be cleaned up by the caller's finally block
            pass

    def start_workflow(self):
        if not self.path_lcpl:
            messagebox.showwarning("文件缺失", "请先选择一个 .lcpl 文件。")
            return

        self.btn_start_decrypt.config(state=tk.DISABLED)
        self.update_status("正在准备解密流程...")
        self.update_progress(0)

        initial_passphrase = self.passphrase if self.passphrase else ""
        passphrase_input = simpledialog.askstring(
            "密码输入",
            "请输入您的 LCP 密码:",
            initialvalue=initial_passphrase,
            show='*'
        )

        if not passphrase_input:
            self.update_status("操作取消: 未输入密码。")
            self.update_progress(0)
            self.btn_start_decrypt.config(state=tk.NORMAL)
            return

        self.passphrase = passphrase_input
        self.save_passphrase(self.passphrase)

        temp_zip_file_path = None
        lcpl_data = None
        output_folder = None
        temp_dir_obj = None

        try:
            # Step 1: Download and package content
            temp_zip_file_path, lcpl_data, output_folder, temp_dir_obj = self.download_and_package_content(
                self.path_lcpl,
                status_callback=self.update_status,
                progress_callback=lambda val: self.update_progress(int(val * 0.4))
            )

            # Step 2: Decrypt the book using the temporary ZIP
            self.update_status("正在解密加密内容...")
            decrypted_files, additional_files = decryptLCPbook_core(
                temp_zip_file_path,
                lcpl_data,
                [self.passphrase],
                status_callback=self.update_status,
                progress_callback=lambda val: self.update_progress(40 + int(val * 0.6))
            )

            self.update_status("解密完成，正在保存文件...")
            self.update_progress(95)

            os.makedirs(output_folder, exist_ok=True)

            for filename, data in decrypted_files.items():
                file_output_path = os.path.join(output_folder, filename)
                os.makedirs(os.path.dirname(file_output_path), exist_ok=True)
                with open(file_output_path, 'wb') as f:
                    f.write(data)
                self.update_status(f"已保存解密文件: {filename}")

            for filename, data in additional_files.items():
                file_output_path = os.path.join(output_folder, filename)
                os.makedirs(os.path.dirname(file_output_path), exist_ok=True)
                with open(file_output_path, 'wb') as f:
                    f.write(data)
                self.update_status(f"已保存附加文件: {filename}")

            messagebox.showinfo("解密成功", f"书籍已成功解密并提取到:\n{output_folder}")
            self.update_status("解密完成！")
            self.update_progress(100)

        except LCPError as e:
            messagebox.showerror("解密错误", f"解密失败: {e}")
            self.update_status("解密失败。")
            self.update_progress(0)
        except Exception as e:
            messagebox.showerror("意外错误", f"发生意外错误: {e}")
            self.update_status("发生未知错误。")
            self.update_progress(0)
        finally:
            self.btn_start_decrypt.config(state=tk.NORMAL)
            if temp_dir_obj:
                temp_dir_obj.cleanup()  # Ensure temp directory is cleaned up


if __name__ == '__main__':
    root = tk.Tk()
    # Apply a theme for better aesthetics (e.g., 'clam', 'alt', 'default', 'classic', 'vista', 'xpnative')
    # Windows 7 supports 'vista' or 'xpnative' themes, 'clam' is cross-platform.
    # We'll stick to a common cross-platform theme for general compatibility.
    # On Windows 7, ttk will automatically use a somewhat native look.
    # No explicit theme setting is strictly necessary unless you want a very specific look.
    # style = ttk.Style()
    # style.theme_use('clam')
    app = App(root)
    root.mainloop()