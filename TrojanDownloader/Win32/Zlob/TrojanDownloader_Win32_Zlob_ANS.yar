
rule TrojanDownloader_Win32_Zlob_ANS{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 54 48 5f 53 54 4f 50 5f 5f 00 } //3 彟䡔卟佔彐_
		$a_01_1 = {5f 5f 50 4d 5f 4d 4f 4e 49 54 4f 52 5f 53 54 4f 50 5f 5f 00 } //3 彟䵐䵟乏呉剏卟佔彐_
		$a_01_2 = {5f 5f 48 49 52 45 5f 5f 00 } //3
		$a_01_3 = {4c 00 4f 00 48 00 49 00 00 00 } //3
		$a_01_4 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //1 Shell_TrayWnd
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_6 = {25 73 61 73 77 65 25 64 2e 65 78 25 73 } //3 %saswe%d.ex%s
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3) >=7
 
}
rule TrojanDownloader_Win32_Zlob_ANS_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0c 00 00 "
		
	strings :
		$a_00_0 = {72 6d 64 69 72 20 22 25 73 22 } //1 rmdir "%s"
		$a_00_1 = {25 64 2e 65 78 65 } //1 %d.exe
		$a_00_2 = {65 76 63 2e 70 68 70 3f 69 64 3d 64 77 30 25 64 } //1 evc.php?id=dw0%d
		$a_00_3 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 75 6e 70 72 6f 74 65 63 74 65 64 20 66 72 6f 6d 20 6e 65 77 20 76 65 72 73 69 6f 6e 20 6f 66 20 53 70 79 42 6f 74 40 4d 58 74 } //1 Your system is unprotected from new version of SpyBot@MXt
		$a_02_4 = {53 70 79 42 6f 74 40 4d 58 74 20 69 73 20 61 20 (6d 61 6c 77 61 72 65 20 70 72 6f 67 72 61 6d|74 72 6f 6a 61 6e 20 68 6f 72 73 65) 20 74 68 61 74 20 73 74 65 61 6c 73 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 61 6e 64 20 67 61 74 68 65 72 73 } //1
		$a_00_5 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 70 72 6f 62 61 62 6c 79 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 6c 61 74 65 73 74 20 76 65 72 73 69 6f 6e 20 6f 66 20 53 70 79 77 61 72 65 2e 43 79 62 65 72 4c 6f 67 2d 58 2e } //1 Your system is probably infected with latest version of Spyware.CyberLog-X.
		$a_00_6 = {67 61 74 65 76 63 2e 70 68 70 3f 70 6e 3d 73 72 63 68 30 70 25 64 74 6f 74 61 6c } //1 gatevc.php?pn=srch0p%dtotal
		$a_00_7 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 6c 61 73 74 20 76 65 72 73 69 6f 6e 20 6f 66 20 50 53 57 2e 78 2d 56 69 72 20 74 72 6f 6a 61 6e 2e 20 50 53 57 20 74 72 6f 6a 61 6e 73 20 73 74 65 61 6c 20 79 6f 75 72 20 70 72 69 76 61 74 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 73 75 63 68 20 61 73 3a 20 70 61 73 73 77 6f 72 64 73 2c 20 49 50 2d 61 64 64 72 65 73 73 2c 20 63 72 65 64 69 74 20 63 61 72 64 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2c 20 72 65 67 69 73 74 72 61 74 69 6f 6e 20 64 65 74 61 69 6c 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 65 74 63 2e } //1 Your computer is infected with last version of PSW.x-Vir trojan. PSW trojans steal your private information such as: passwords, IP-address, credit card information, registration details, documents, etc.
		$a_00_8 = {53 79 73 74 65 6d 20 41 6c 65 72 74 3a 20 54 72 6f 6a 61 6e 2d 53 70 79 2e 57 69 6e 33 32 40 6d 78 } //1 System Alert: Trojan-Spy.Win32@mx
		$a_00_9 = {53 65 63 75 72 69 74 79 20 41 6c 65 72 74 3a 20 4e 65 74 57 6f 72 6d 2d 69 2e 56 69 72 75 73 40 66 70 } //1 Security Alert: NetWorm-i.Virus@fp
		$a_00_10 = {25 64 2e 62 61 74 } //1 %d.bat
		$a_00_11 = {2f 66 69 6c 65 73 2f 67 65 74 2e 70 68 70 3f } //1 /files/get.php?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=8
 
}