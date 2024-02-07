
rule TrojanSpy_BAT_Keylogger_AR{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4c 6f 67 67 65 72 } //01 00  KeyLogger
		$a_01_1 = {55 73 65 72 41 63 74 69 76 69 74 79 48 6f 6f 6b } //01 00  UserActivityHook
		$a_01_2 = {53 65 6e 64 4d 61 69 6c 49 6d 61 67 65 } //01 00  SendMailImage
		$a_01_3 = {5b 00 50 00 72 00 69 00 6e 00 74 00 53 00 63 00 72 00 65 00 65 00 6e 00 5d 00 } //01 00  [PrintScreen]
		$a_01_4 = {69 00 6d 00 61 00 67 00 65 00 6e 00 2e 00 6a 00 70 00 67 00 } //01 00  imagen.jpg
		$a_01_5 = {40 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  @hotmail.com
		$a_01_6 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_7 = {5d 04 00 00 } //8a 1c 
	condition:
		any of ($a_*)
 
}