
rule Trojan_Win32_Vidar_AAD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,36 00 36 00 0e 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 26 20 72 64 20 2f 73 20 2f 71 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //10 /c timeout /t 10 & rd /s /q "C:\ProgramData\
		$a_01_1 = {52 65 6c 65 61 73 65 5c 76 64 72 31 2e 70 64 62 } //10 Release\vdr1.pdb
		$a_01_2 = {76 64 72 31 2e 65 78 65 } //10 vdr1.exe
		$a_01_3 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //5 \Monero\wallet.keys
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 } //5 SOFTWARE\monero-project\monero-cor
		$a_01_5 = {5f 63 6f 6f 6b 69 65 73 2e 64 62 } //2 _cookies.db
		$a_01_6 = {5f 70 61 73 73 77 6f 72 64 73 2e 64 62 } //2 _passwords.db
		$a_01_7 = {5f 6b 65 79 34 2e 64 62 } //2 _key4.db
		$a_01_8 = {5f 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //2 _logins.json
		$a_01_9 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //2 passwords.txt
		$a_01_10 = {55 73 65 4d 61 73 74 65 72 50 61 73 73 77 6f 72 64 } //1 UseMasterPassword
		$a_01_11 = {43 72 61 73 68 20 44 65 74 65 63 74 65 64 } //1 Crash Detected
		$a_01_12 = {68 74 74 70 73 3a 2f 2f 73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d } //1 https://steamcommunity.com
		$a_01_13 = {68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f } //1 https://t.me/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=54
 
}