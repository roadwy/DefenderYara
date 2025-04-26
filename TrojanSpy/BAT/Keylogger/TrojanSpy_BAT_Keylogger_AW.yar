
rule TrojanSpy_BAT_Keylogger_AW{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 67 65 72 } //1 Logger
		$a_01_1 = {63 61 6d 5f 6c 69 73 74 65 6e 65 72 } //1 cam_listener
		$a_01_2 = {54 61 6b 65 53 63 72 65 65 6e 53 68 6f 74 } //1 TakeScreenShot
		$a_01_3 = {55 00 41 00 48 00 20 00 69 00 73 00 20 00 45 00 4e 00 41 00 42 00 4c 00 45 00 44 00 } //1 UAH is ENABLED
		$a_01_4 = {53 00 45 00 4e 00 44 00 49 00 4e 00 47 00 20 00 46 00 49 00 4c 00 45 00 20 00 45 00 52 00 52 00 4f 00 52 00 } //1 SENDING FILE ERROR
		$a_01_5 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}