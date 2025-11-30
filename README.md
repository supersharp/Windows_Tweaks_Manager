# Windows Master Tweak Utility

## 📖 Description
This is an all-in-one utility designed to optimise, debloat, and enhance your Windows experience. It automates complex tasks like editing the registry, removing unwanted apps, and adding useful shortcuts to streamline your workflow.

<img width="974" height="510" alt="image" src="https://github.com/user-attachments/assets/a69d667f-e83e-4433-a449-990884db6cc8" />


## 🚀 How to Use
1.  **Download:** Ensure the `Resources` folder is located in the same directory as the script. I can't upload the .lnk files to the repository; they are included in the release zip file
2.  **Run:** Right-click `Run.bat` and select **Run as Administrator**.
3.  **Select:** Follow the on-screen menu to apply or revert tweaks.

---

## 🛠️ Menu Options Explained

### `[1]` Install 'Open Terminal (Admin)' Context Menu
* Adds a new option to your right-click context menu: **"Open in Terminal (Admin)"**.
* **Supports:** Folders, empty backgrounds, and specifically `.ps1` (PowerShell), `.bat`, and `.cmd` scripts.

  <img width="209" height="325" alt="image" src="https://github.com/user-attachments/assets/c12b6086-84f2-4104-bd9d-66b79e226500" />


### `[2]` Apply System Tweaks, Startup Tasks, Shortcuts, DNS & Take Ownership
This is the main optimisation option. It performs the following:

#### 🧹 System Cleanup (Debloat)
* **Removes Bloatware:** Disables built-in ads like "Copilot", "Recall", Edge Sidebar, and Search suggestions.
* **Xbox Cleanup:** Uninstalls all pre-installed Xbox apps to save system resources.
* **Gaming Performance:** Disables "Game DVR" background recording to improve gaming performance.

#### 🖥️ UI Improvements
* **Classic Menu:** Restores the classic "Windows 10 style" right-click menu (removes "Show more options").
* **Explorer Cleanup:** Hides "Home" and "Gallery" from File Explorer.
* **Windows Settings Cleanup:** Removes "Home" from Windows 11 settings
* **Menu Declutter:** Removes "Create new shortcut", "Troubleshoot Compatibility", "Restore previous version", "Pin to Quick Access", and "Add to Favorites".

#### ⚡ Useful Additions
* **Take Ownership:** Adds a context menu option to help delete stubborn files or folders.

  <img width="208" height="500" alt="image" src="https://github.com/user-attachments/assets/baa8492c-d2e9-4520-b124-58034a7808cc" />

* **Shortcuts:** Creates shortcuts for Windows Update, Microsoft Store, and Realtek Audio in your Start Menu.
* **Audio Optimisation:** Configures a startup task for **Low Audio Latency** (improves sound response).

  `LowAudioLatency sets the Windows audio buffer to the smallest possible value, similar to miniant-git/REAL. LAL not only checks the output devices (headphones, speakers) but also the input devices (microphones). 
  Additionally, it removes the real-time connection to the first CPU thread, as it is not necessary for this function. If the smallest buffer size is already the default buffer size, the program will terminate.`

#### 🔒 Network Security
* **Secure DNS:** Configures DNS-over-HTTPS (DoH) using Cloudflare and Google.
* **Privacy:** Encrypts your internet requests, it can also help bypass DNS blocks by your ISP.

### `[3]` Revert 'Open Terminal (Admin)' Context Menu
* Removes the custom "Open in Terminal" options added by Option `[1]`.

### `[4]` Revert System Tweaks
* Undoes the changes made by Option `[2]`.
* Re-enables Copilot, Game DVR, and restores the default Windows 11 right-click menu.
* Removes the shortcuts and custom DNS settings.
* *Note: This does NOT automatically reinstall Xbox apps (use Option `[5]` for that).*

### `[5]` Re-install Xbox / Microsoft Store Dependencies
* **Winget Installation:** Automatically downloads and installs the official Xbox App, Game Bar, and Gaming Services directly from Microsoft servers.
* **Repairs:** Fixes broken Microsoft Store or Gaming Services installations.
* **Registry Fix:** Re-enables the Game Bar registry keys so you can record clips again.

---

## 🏆 Credits

**Low Audio Latency Utility**
This script utilises the **LowAudioLatency** utility to improve audio response times.
* **Author:** spddl
* **Version Used:** v3.1.0 - PreRelease (noconsole version)
* **Source:** [https://github.com/spddl/LowAudioLatency/releases](https://github.com/spddl/LowAudioLatency/releases)

---

## ⚠️ Disclaimer
*Always create a System Restore point before applying registry tweaks.*
