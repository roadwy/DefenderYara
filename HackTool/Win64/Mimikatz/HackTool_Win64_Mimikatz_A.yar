
rule HackTool_Win64_Mimikatz_A{
	meta:
		description = "HackTool:Win64/Mimikatz.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 14 00 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 46 69 6c 65 5a 69 6c 6c 61 2e 64 61 74 } //AppData\Roaming\FileZilla.dat  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 65 64 65 6e 74 69 61 6c } //AppData\Local\Microsoft\Credential  1
		$a_80_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //Application Data\Thunderbird\Profiles  1
		$a_80_3 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //AppData\Roaming\Thunderbird\Profiles  1
		$a_80_4 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //AppData\Roaming\Mozilla\Firefox\Profiles  1
		$a_80_5 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //Application Data\Mozilla\Firefox\Profiles  1
		$a_80_6 = {4f 75 74 6c 6f 6f 6b 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //Outlook\Profiles\Outlook  1
		$a_80_7 = {53 4f 46 54 57 41 52 45 5c 52 65 61 6c 56 4e 43 5c 57 69 6e 56 4e 43 34 } //SOFTWARE\RealVNC\WinVNC4  1
		$a_80_8 = {41 64 6d 69 6e 50 61 73 73 77 6f 72 64 } //AdminPassword  1
		$a_80_9 = {53 4f 46 54 57 41 52 45 5c 54 69 67 68 74 56 4e 43 5c 53 65 72 76 65 72 } //SOFTWARE\TightVNC\Server  1
		$a_80_10 = {75 76 6e 63 20 62 76 62 61 5c 55 6c 74 72 61 56 4e 43 5c 55 6c 74 72 61 56 4e 43 2e 69 6e 69 } //uvnc bvba\UltraVNC\UltraVNC.ini  1
		$a_80_11 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 5c 4c 6f 67 69 6e 20 44 61 74 61 } //AppData\Roaming\Opera Software\Opera Stable\Login Data  1
		$a_80_12 = {53 45 4c 45 43 54 20 68 6f 73 74 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins  1
		$a_80_13 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //Software\Microsoft\Internet Explorer\IntelliForms\Storage2  1
		$a_80_14 = {4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //Local Settings\Application Data\Google\Chrome\User Data\Default\  1
		$a_80_15 = {41 70 70 64 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //Appdata\Local\Google\Chrome\User Data\Default\  1
		$a_80_16 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook  1
		$a_80_17 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 72 6f 66 69 6c 65 4c 69 73 74 5c } //SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\  1
		$a_80_18 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 65 62 43 61 63 68 65 5c 57 65 62 43 61 63 68 65 56 30 31 2e 64 61 74 } //AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat  1
		$a_80_19 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT origin_url, username_value, password_value FROM logins  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1) >=6
 
}