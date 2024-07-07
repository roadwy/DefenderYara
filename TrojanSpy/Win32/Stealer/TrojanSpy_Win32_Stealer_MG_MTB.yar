
rule TrojanSpy_Win32_Stealer_MG_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {51 53 41 77 4c 6a 41 75 4d 77 3d 3d } //1 QSAwLjAuMw==
		$a_01_3 = {3c 70 61 73 73 77 6f 72 64 3e } //1 <password>
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 SELECT * FROM AntiVirusProduct
		$a_01_5 = {72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 } //1 root\SecurityCenter2
		$a_01_6 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 46 69 72 65 77 61 6c 6c 50 72 6f 64 75 63 74 } //1 SELECT * FROM FirewallProduct
		$a_01_7 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 64 65 6c 65 74 65 20 2f 66 20 2f 74 6e 20 50 69 72 61 74 65 } //1 schtasks.exe /delete /f /tn Pirate
		$a_01_8 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_01_9 = {43 72 79 70 74 44 65 73 74 72 6f 79 48 61 73 68 } //1 CryptDestroyHash
		$a_01_10 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}