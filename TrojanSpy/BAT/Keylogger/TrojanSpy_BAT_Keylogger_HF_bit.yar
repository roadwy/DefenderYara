
rule TrojanSpy_BAT_Keylogger_HF_bit{
	meta:
		description = "TrojanSpy:BAT/Keylogger.HF!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 64 00 61 00 74 00 65 00 78 00 73 00 6c 00 2e 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  \datexsl.system
		$a_01_1 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  smtp.gmail.com
		$a_01_2 = {20 00 2f 00 43 00 4c 00 49 00 43 00 4b 00 2f 00 20 00 } //01 00   /CLICK/ 
		$a_01_3 = {75 00 70 00 64 00 61 00 74 00 65 00 20 00 2d 00 20 00 } //01 00  update - 
		$a_01_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}