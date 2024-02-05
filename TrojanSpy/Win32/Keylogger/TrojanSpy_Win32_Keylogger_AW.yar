
rule TrojanSpy_Win32_Keylogger_AW{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AW,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6f 70 70 69 74 72 6f 6e 69 63 2e 6e 65 74 2f 68 69 64 64 65 6e 2f 70 6f 63 2f 6c 6f 67 63 68 2e 70 68 70 } //01 00 
		$a_01_1 = {48 61 68 61 2c 20 49 27 6d 20 73 74 69 6c 6c 20 74 68 65 72 65 } //01 00 
		$a_01_2 = {6b 65 79 73 74 72 6f 6b 65 20 73 70 79 } //00 00 
	condition:
		any of ($a_*)
 
}