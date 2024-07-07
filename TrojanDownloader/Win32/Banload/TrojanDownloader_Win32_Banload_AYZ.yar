
rule TrojanDownloader_Win32_Banload_AYZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AYZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6f 67 6c 6f 62 6f 2e 67 6c 6f 62 6f 2e 63 6f 6d 2f 62 72 61 73 69 6c 2f } //1 http://oglobo.globo.com/brasil/
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 } //1 reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v
		$a_01_2 = {5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 \Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
		$a_01_3 = {78 2e 63 70 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}