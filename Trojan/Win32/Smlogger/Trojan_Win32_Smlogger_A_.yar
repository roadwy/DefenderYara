
rule Trojan_Win32_Smlogger_A_{
	meta:
		description = "Trojan:Win32/Smlogger.A!!Smlogger.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4b 65 79 6c 6f 67 67 65 72 20 41 6e 64 20 43 6c 69 70 62 6f 61 72 64 } //01 00  Keylogger And Clipboard
		$a_81_1 = {54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 } //01 00  Telegram Desktop
		$a_81_2 = {44 69 73 63 6f 72 64 20 54 6f 6b 6b 65 6e } //01 00  Discord Tokken
		$a_81_3 = {53 65 61 72 63 68 20 41 6e 64 20 55 70 6c 6f 61 64 } //01 00  Search And Upload
		$a_81_4 = {53 63 72 65 65 6e 73 68 6f 74 2e 6a 70 65 67 } //01 00  Screenshot.jpeg
		$a_81_5 = {5c 4c 6f 67 2e 74 78 74 } //01 00  \Log.txt
		$a_81_6 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //00 00  AppData\Roaming\Thunderbird\Profiles
	condition:
		any of ($a_*)
 
}