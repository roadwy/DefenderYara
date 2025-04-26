
rule Trojan_Win32_TurlaCarbon_A_{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5b 43 54 52 4c 2b 42 52 45 41 4b 20 50 52 4f 43 45 53 53 49 4e 47 5d } //1 [CTRL+BREAK PROCESSING]
		$a_00_1 = {5b 49 4d 45 20 4a 55 4e 4a 41 20 4d 4f 44 45 5d } //1 [IME JUNJA MODE]
		$a_00_2 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 64 20 70 72 6f 63 65 73 73 20 77 69 74 68 20 64 75 70 6c 69 63 61 74 65 64 20 74 6f 6b 65 6e 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a 20 } //1 Failed to created process with duplicated token. Error code: 
		$a_00_3 = {53 65 74 20 68 6f 6f 6b 73 } //1 Set hooks
		$a_00_4 = {45 72 72 6f 72 20 67 65 74 74 69 6e 67 20 74 65 6d 70 20 70 61 74 68 3a } //1 Error getting temp path:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_TurlaCarbon_A__2{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? bf 08 00 00 00 48 89 75 00 48 bb 64 65 6c 5f 74 61 73 6b } //1
		$a_01_1 = {bb 04 00 00 00 48 89 75 00 48 8d 54 24 50 48 89 5d f8 48 8d 4d a8 c7 45 e8 6e 61 6d 65 44 88 65 ec e8 } //1
		$a_01_2 = {55 70 6c 6f 61 64 69 6e 67 3a 20 } //1 Uploading: 
		$a_01_3 = {44 65 6c 65 74 69 6e 67 3a 20 } //1 Deleting: 
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 3a 20 } //1 Downloading: 
		$a_01_5 = {4c 69 73 74 20 66 69 6c 65 73 20 66 6f 72 3a 20 } //1 List files for: 
		$a_01_6 = {7b 22 55 55 49 44 22 3a 22 00 } //1 ≻啕䑉㨢"
		$a_01_7 = {22 2c 20 22 64 61 74 61 22 3a 22 00 } //1 Ⱒ∠慤慴㨢"
		$a_01_8 = {22 2c 20 22 74 79 70 65 22 3a 22 00 } //1 Ⱒ∠祴数㨢"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule Trojan_Win32_TurlaCarbon_A__3{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 52 65 73 53 76 63 } //1 WinResSvc
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 4d 53 53 56 43 43 46 47 2e 64 6c 6c } //1 C:\Program Files\Windows NT\MSSVCCFG.dll
		$a_00_2 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 75 70 20 73 65 72 76 69 63 65 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a 20 25 64 } //1 Failed to set up service. Error code: %d
		$a_00_3 = {56 69 72 74 75 61 6c 51 75 65 72 79 20 66 61 69 6c 65 64 20 66 6f 72 20 25 64 20 62 79 74 65 73 20 61 74 20 61 64 64 72 65 73 73 20 25 70 } //1 VirtualQuery failed for %d bytes at address %p
		$a_00_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 30 78 25 78 } //1 VirtualProtect failed with code 0x%x
		$a_00_5 = {25 70 20 6e 6f 74 20 66 6f 75 6e 64 3f 21 3f 21 } //1 %p not found?!?!
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule Trojan_Win32_TurlaCarbon_A__4{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 00 69 00 70 00 65 00 5c 00 63 00 6f 00 6d 00 6d 00 63 00 74 00 72 00 6c 00 64 00 65 00 76 00 } //1 pipe\commctrldev
		$a_00_1 = {70 00 69 00 70 00 65 00 5c 00 63 00 6f 00 6d 00 6d 00 73 00 65 00 63 00 64 00 65 00 76 00 } //1 pipe\commsecdev
		$a_00_2 = {69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 installer.exe
		$a_00_3 = {43 6f 75 6c 64 20 6e 6f 74 20 64 65 6c 65 74 65 20 7b 7d 5c 7b 7d 2e 73 79 73 } //1 Could not delete {}\{}.sys
		$a_00_4 = {69 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //2 installer.pdb
		$a_00_5 = {2f 00 50 00 55 00 42 00 2f 00 68 00 6f 00 6d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //2 /PUB/home.html
		$a_00_6 = {63 00 68 00 65 00 61 00 70 00 69 00 6e 00 66 00 6f 00 6d 00 65 00 64 00 69 00 63 00 61 00 6c 00 39 00 39 00 2e 00 6e 00 65 00 74 00 } //2 cheapinfomedical99.net
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2) >=8
 
}
rule Trojan_Win32_TurlaCarbon_A__5{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4e 38 43 72 79 70 74 6f 50 50 31 32 43 41 53 54 31 32 38 5f 49 6e 66 6f 45 } //1 N8CryptoPP12CAST128_InfoE
		$a_00_1 = {25 70 20 6e 6f 74 20 66 6f 75 6e 64 3f 21 3f 21 } //1 %p not found?!?!
		$a_00_2 = {54 25 70 20 25 64 20 56 3d 25 30 58 20 48 3d 25 70 20 25 73 } //1 T%p %d V=%0X H=%p %s
		$a_00_3 = {5b 54 41 53 4b 5d 20 4f 75 74 70 75 74 74 69 6e 67 20 74 6f 20 73 65 6e 64 20 66 69 6c 65 3a } //1 [TASK] Outputting to send file:
		$a_00_4 = {5b 54 41 53 4b 5d 20 43 6f 6d 6d 73 20 6c 69 62 20 61 63 74 69 76 65 2c 20 70 65 72 66 6f 72 6d 69 6e 67 20 74 61 73 6b 69 6e 67 20 63 68 65 63 6b 73 } //1 [TASK] Comms lib active, performing tasking checks
		$a_00_5 = {5b 54 41 53 4b 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 67 65 74 20 6f 77 6e 65 72 73 68 69 70 20 6f 66 20 6d 75 74 65 78 3a } //1 [TASK] Attempting to get ownership of mutex:
		$a_00_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 68 69 73 74 6f 72 79 2e 6a 70 67 } //1 C:\Program Files\Windows NT\history.jpg
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule Trojan_Win32_TurlaCarbon_A__6{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_00_0 = {46 61 69 6c 65 64 20 74 6f 20 70 61 72 73 65 20 62 65 61 63 6f 6e 20 72 65 73 70 6f 6e 73 65 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a } //1 Failed to parse beacon response. Error code:
		$a_00_1 = {48 65 61 72 74 62 65 61 74 20 66 61 69 6c 65 64 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a } //1 Heartbeat failed. Error code:
		$a_00_2 = {54 72 75 6e 63 61 74 65 64 20 70 69 70 65 20 73 65 72 76 65 72 20 6c 6f 67 20 66 69 6c 65 2e } //1 Truncated pipe server log file.
		$a_00_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 75 70 6c 6f 61 64 65 64 20 43 32 20 6c 6f 67 20 66 69 6c 65 2e } //1 Successfully uploaded C2 log file.
		$a_00_4 = {44 6f 77 6e 6c 6f 61 64 65 64 20 70 61 79 6c 6f 61 64 3a } //1 Downloaded payload:
		$a_00_5 = {44 69 73 63 6f 76 65 72 65 64 20 63 6f 6d 70 75 74 65 72 20 6e 61 6d 65 3a } //1 Discovered computer name:
		$a_00_6 = {53 65 74 20 69 6d 70 6c 61 6e 74 20 49 44 20 74 6f } //1 Set implant ID to
		$a_00_7 = {52 65 63 65 69 76 65 64 20 65 6d 70 74 79 20 69 6e 74 72 75 63 74 69 6f 6e 2e 20 57 69 6c 6c 20 66 6f 72 77 61 72 64 20 74 6f 20 65 78 65 63 75 74 6f 72 20 63 6c 69 65 6e 74 2e } //1 Received empty intruction. Will forward to executor client.
		$a_00_8 = {46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 74 61 73 6b 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a } //1 Failed to execute task. Error code:
		$a_00_9 = {63 68 65 63 6b 6d 61 74 65 4e 41 53 41 } //1 checkmateNASA
		$a_00_10 = {5b 00 45 00 52 00 52 00 4f 00 52 00 5d 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 77 00 61 00 69 00 74 00 20 00 66 00 6f 00 72 00 20 00 6d 00 75 00 74 00 65 00 78 00 2e 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 64 00 65 00 3a 00 20 00 } //1 [ERROR] Failed to wait for mutex. Error code: 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=10
 
}
rule Trojan_Win32_TurlaCarbon_A__7{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 31 30 38 2e 30 2e 30 2e 30 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 20 45 64 67 2f 31 30 38 2e 30 2e 31 34 36 32 2e 35 34 } //1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54
		$a_00_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 44 00 72 00 69 00 76 00 65 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 53 00 74 00 64 00 } //1 Global\DriveEncryptionStd
		$a_00_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 44 00 72 00 69 00 76 00 65 00 48 00 65 00 61 00 6c 00 74 00 68 00 4f 00 76 00 65 00 72 00 77 00 61 00 74 00 63 00 68 00 } //1 Global\DriveHealthOverwatch
		$a_00_3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 54 00 65 00 6c 00 65 00 6d 00 65 00 74 00 72 00 79 00 2e 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Global\Microsoft.Telemetry.Configuration
		$a_00_4 = {77 6f 72 6b 64 69 63 74 2e 78 6d 6c } //1 workdict.xml
		$a_00_5 = {43 57 5f 4c 4f 43 41 4c } //1 CW_LOCAL
		$a_00_6 = {43 57 5f 49 4e 45 54 } //1 CW_INET
		$a_00_7 = {5b 50 32 50 20 48 41 4e 44 4c 45 52 5d } //1 [P2P HANDLER]
		$a_00_8 = {2f 6a 61 76 61 73 63 72 69 70 74 2f 76 69 65 77 2e 70 68 70 00 } //1
		$a_00_9 = {74 72 61 6e 73 5f 74 69 6d 65 6d 61 78 00 } //1 牴湡彳楴敭慭x
		$a_00_10 = {73 79 73 74 65 6d 5f 70 69 70 65 00 } //1 祳瑳浥灟灩e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=9
 
}
rule Trojan_Win32_TurlaCarbon_A__8{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0d 00 0d 00 0b 00 00 "
		
	strings :
		$a_00_0 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 36 00 34 00 3b 00 20 00 78 00 36 00 34 00 29 00 20 00 41 00 70 00 70 00 6c 00 65 00 57 00 65 00 62 00 4b 00 69 00 74 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 20 00 28 00 4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 29 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 31 00 30 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 } //1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
		$a_00_1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 36 00 34 00 3b 00 20 00 78 00 36 00 34 00 3b 00 20 00 72 00 76 00 3a 00 31 00 30 00 36 00 2e 00 30 00 29 00 20 00 47 00 65 00 63 00 6b 00 6f 00 2f 00 32 00 30 00 31 00 30 00 30 00 31 00 30 00 31 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2f 00 31 00 30 00 36 00 2e 00 30 00 } //1 Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
		$a_00_2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 3b 00 20 00 54 00 72 00 69 00 64 00 65 00 6e 00 74 00 2f 00 37 00 2e 00 30 00 3b 00 20 00 72 00 76 00 3a 00 31 00 31 00 2e 00 30 00 29 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 } //1 Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko
		$a_00_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 51 00 36 00 30 00 38 00 33 00 31 00 37 00 24 00 } //2 C:\Windows\$NtUninstallQ608317$
		$a_00_4 = {53 65 74 20 69 6d 70 6c 61 6e 74 20 49 44 20 74 6f 20 } //2 Set implant ID to 
		$a_00_5 = {53 68 65 6c 6c 20 43 6f 6d 6d 61 6e 64 3a 20 } //2 Shell Command: 
		$a_00_6 = {52 75 6e 20 61 73 20 75 73 65 72 3a 20 } //2 Run as user: 
		$a_00_7 = {55 70 6c 6f 61 64 20 66 69 6c 65 } //2 Upload file
		$a_00_8 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 57 00 69 00 6e 00 42 00 61 00 73 00 65 00 53 00 76 00 63 00 44 00 42 00 4c 00 6f 00 63 00 6b 00 } //1 Global\WinBaseSvcDBLock
		$a_00_9 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 43 00 6f 00 6d 00 6d 00 43 00 74 00 72 00 6c 00 44 00 42 00 } //1 Global\WindowsCommCtrlDB
		$a_00_10 = {2f 00 49 00 4d 00 41 00 47 00 45 00 53 00 2f 00 33 00 2f 00 } //1 /IMAGES/3/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=13
 
}
rule Trojan_Win32_TurlaCarbon_A__9{
	meta:
		description = "Trojan:Win32/TurlaCarbon.A!!TurlaCarbon.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,23 00 23 00 23 00 00 "
		
	strings :
		$a_80_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 73 65 72 76 69 63 65 73 5c 57 69 6e 52 65 73 53 76 63 5c 50 61 72 61 6d 65 74 65 72 73 } //SYSTEM\CurrentControlSet\services\WinResSvc\Parameters  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost  1
		$a_80_2 = {53 65 74 20 76 69 63 74 69 6d 20 55 55 49 44 20 74 6f } //Set victim UUID to  1
		$a_80_3 = {53 65 74 20 75 70 20 70 65 65 72 20 74 6f 20 70 65 65 72 } //Set up peer to peer  1
		$a_80_4 = {53 61 76 65 64 20 74 61 73 6b 20 66 72 6f 6d 20 70 65 65 72 } //Saved task from peer  1
		$a_80_5 = {53 61 76 65 64 20 74 61 73 6b 20 66 72 6f 6d 20 43 32 20 73 65 72 76 65 72 } //Saved task from C2 server  1
		$a_80_6 = {53 61 76 69 6e 67 20 70 61 79 6c 6f 61 64 20 74 6f } //Saving payload to  1
		$a_80_7 = {2f 6a 61 76 61 73 63 72 69 70 74 2f 76 69 65 77 2e 70 68 70 } ///javascript/view.php  1
		$a_80_8 = {5b 57 41 52 4e 2d 49 4e 4a 5d 20 52 65 69 6e 6a 65 63 74 69 6e 67 20 64 75 65 20 74 6f 20 65 72 72 6f 72 2c 20 73 65 65 20 65 72 72 6f 72 20 6c 6f 67 } //[WARN-INJ] Reinjecting due to error, see error log  1
		$a_80_9 = {5b 57 41 52 4e 2d 49 4e 4a 5d 20 47 65 74 50 72 6f 63 65 73 73 56 65 63 74 6f 72 73 48 61 6e 64 6c 65 50 49 44 73 50 50 49 44 73 20 66 61 69 6c 65 64 20 66 6f 72 20 70 72 6f 63 65 73 73 20 } //[WARN-INJ] GetProcessVectorsHandlePIDsPPIDs failed for process   1
		$a_80_10 = {5b 57 41 52 4e 2d 54 41 53 4b 5d 20 55 6e 61 62 6c 65 20 74 6f 20 62 75 69 6c 64 20 74 61 73 6b 20 66 72 6f 6d 20 6c 69 6e 65 2c 20 65 72 72 6f 72 3a 20 } //[WARN-TASK] Unable to build task from line, error:   1
		$a_80_11 = {5b 54 41 53 4b 5d 20 54 61 73 6b 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 62 75 69 6c 74 } //[TASK] Task successfully built  1
		$a_80_12 = {5b 54 41 53 4b 5d 20 54 61 73 6b 20 63 6f 6e 66 69 67 3a } //[TASK] Task config:  1
		$a_80_13 = {5b 54 41 53 4b 5d 20 52 65 6c 65 61 73 69 6e 67 20 6d 75 74 65 78 2c 20 73 6c 65 65 70 69 6e 67 2e 2e 2e } //[TASK] Releasing mutex, sleeping...  1
		$a_80_14 = {5b 54 41 53 4b 5d 20 52 65 63 69 65 76 65 64 20 74 61 73 6b 20 6c 69 6e 65 3a 20 } //[TASK] Recieved task line:   1
		$a_80_15 = {5b 54 41 53 4b 5d 20 50 61 79 6c 6f 61 64 20 66 69 6c 65 70 61 74 68 3a 20 } //[TASK] Payload filepath:   1
		$a_80_16 = {5b 54 41 53 4b 5d 20 4f 72 63 68 65 73 74 72 61 74 6f 72 20 74 61 73 6b 20 66 69 6c 65 20 73 69 7a 65 3a 20 } //[TASK] Orchestrator task file size:   1
		$a_80_17 = {5b 54 41 53 4b 5d 20 43 6f 6d 6d 73 20 6c 69 62 20 69 6e 61 63 74 69 76 65 2c 20 73 6c 65 65 70 69 6e 67 } //[TASK] Comms lib inactive, sleeping  1
		$a_80_18 = {5b 54 41 53 4b 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 67 65 74 20 6f 77 6e 65 72 73 68 69 70 20 6f 66 20 6d 75 74 65 78 3a 20 } //[TASK] Attempting to get ownership of mutex:   1
		$a_80_19 = {5b 4f 52 43 48 5d 20 53 65 6e 64 20 66 69 6c 65 20 70 61 74 68 3a 20 } //[ORCH] Send file path:   1
		$a_80_20 = {5b 4f 52 43 48 5d 20 43 6f 6e 66 69 67 20 63 6f 6e 74 65 6e 74 73 3a } //[ORCH] Config contents:  1
		$a_80_21 = {5b 4d 54 58 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 63 72 65 61 74 65 64 20 6d 75 74 65 78 65 73 } //[MTX] Successfully created mutexes  1
		$a_80_22 = {5b 4d 41 49 4e 5d 20 53 74 61 72 74 69 6e 67 20 69 6e 6a 65 63 74 69 6f 6e 20 6c 6f 6f 70 } //[MAIN] Starting injection loop  1
		$a_80_23 = {5b 49 4e 4a 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 69 6e 6a 65 63 74 20 69 6e 74 6f 20 } //[INJ] Attempting to inject into   1
		$a_80_24 = {5b 45 52 52 4f 52 2d 54 41 53 4b 5d 20 54 61 73 6b 69 6e 67 20 52 65 61 64 54 61 73 6b 46 69 6c 65 20 65 6e 63 6f 75 6e 74 65 72 65 64 20 65 72 72 6f 72 20 72 65 61 64 69 6e 67 20 74 61 73 6b 20 66 69 6c 65 20 } //[ERROR-TASK] Tasking ReadTaskFile encountered error reading task file   1
		$a_80_25 = {5b 45 52 52 4f 52 2d 54 41 53 4b 5d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 20 66 61 69 6c 65 64 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-TASK] CreateProcessA failed. GetLastError:   1
		$a_80_26 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 74 61 72 67 65 74 50 72 6f 63 65 73 73 65 73 20 69 73 20 65 6d 70 74 79 20 61 66 74 65 72 20 61 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 62 75 69 6c 64 20 76 65 63 74 6f 72 2e } //[ERROR-INJ] targetProcesses is empty after attempting to build vector.  1
		$a_80_27 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 74 61 72 67 65 74 50 72 6f 63 4c 69 73 74 20 69 73 20 65 6d 70 74 79 20 61 66 74 65 72 20 47 65 74 43 6f 6e 66 69 67 56 61 6c 75 65 20 63 61 6c 6c 2e } //[ERROR-INJ] targetProcList is empty after GetConfigValue call.  1
		$a_80_28 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-INJ] WriteProcessMemory failed. GetLastError:   1
		$a_80_29 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 55 6e 61 62 6c 65 20 74 6f 20 6c 6f 63 61 74 65 20 44 4c 4c 20 74 6f 20 69 6e 6a 65 63 74 20 61 74 20 70 61 74 68 3a 20 } //[ERROR-INJ] Unable to locate DLL to inject at path:   1
		$a_80_30 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 53 6e 61 70 73 68 6f 74 20 65 6d 70 74 79 20 6f 72 20 69 73 73 75 65 20 77 69 74 68 20 50 72 6f 63 65 73 73 33 32 46 69 72 73 74 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-INJ] Snapshot empty or issue with Process32First. GetLastError:   1
		$a_80_31 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 50 65 72 66 6f 72 6d 49 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 20 66 6f 72 20 70 72 6f 63 65 73 73 20 } //[ERROR-INJ] PerformInjection failed for process   1
		$a_80_32 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 49 6e 6a 65 63 74 69 6f 6e 4d 61 69 6e 20 66 61 69 6c 65 64 20 77 69 74 68 20 65 72 72 6f 72 20 63 6f 64 65 3a 20 } //[ERROR-INJ] InjectionMain failed with error code:   1
		$a_80_33 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 20 66 61 69 6c 65 64 2e 20 47 65 74 4c 61 73 74 45 72 72 6f 72 3a 20 } //[ERROR-INJ] CreateToolhelp32Snapshot failed. GetLastError:   1
		$a_80_34 = {5b 45 52 52 4f 52 2d 49 4e 4a 5d 20 41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 20 66 61 69 6c 65 64 2e 20 52 65 74 75 72 6e 56 61 6c 75 65 3a 20 } //[ERROR-INJ] AdjustTokenPrivileges failed. ReturnValue:   1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1+(#a_80_21  & 1)*1+(#a_80_22  & 1)*1+(#a_80_23  & 1)*1+(#a_80_24  & 1)*1+(#a_80_25  & 1)*1+(#a_80_26  & 1)*1+(#a_80_27  & 1)*1+(#a_80_28  & 1)*1+(#a_80_29  & 1)*1+(#a_80_30  & 1)*1+(#a_80_31  & 1)*1+(#a_80_32  & 1)*1+(#a_80_33  & 1)*1+(#a_80_34  & 1)*1) >=35
 
}