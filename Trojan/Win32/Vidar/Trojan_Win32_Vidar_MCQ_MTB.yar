
rule Trojan_Win32_Vidar_MCQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 4e 54 20 44 45 43 52 59 50 54 20 4b 45 59 } //1 ANT DECRYPT KEY
		$a_01_1 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 47 65 74 4c 61 73 74 49 6e 70 75 74 } //1 GetKeyboardStateGetClipboardDataGetLastInput
		$a_01_2 = {70 72 6f 63 65 73 73 42 72 6f 77 73 65 72 73 5c 4c 6f 67 69 6e 73 5f 24 61 70 70 64 61 74 61 5c 64 69 73 63 6f 72 64 72 65 61 64 } //1 processBrowsers\Logins_$appdata\discordread
		$a_01_3 = {45 6c 65 63 74 72 75 6d 5c 77 61 6c 6c 65 74 73 } //1 Electrum\wallets
		$a_01_4 = {63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 70 61 73 73 77 6f 72 64 } //1 cookies.sqliteloginusers.vdfpassword
		$a_01_5 = {70 72 6f 63 65 73 73 42 72 6f 77 73 65 72 73 5c 4c 6f 67 69 6e 73 5f 24 61 70 70 64 61 74 61 5c 64 69 73 63 6f 72 64 72 65 } //1 processBrowsers\Logins_$appdata\discordre
		$a_01_6 = {68 74 74 70 62 69 62 61 77 69 6e 76 2e 65 78 65 } //1 httpbibawinv.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}