
rule TrojanSpy_BAT_Keylogger_AD{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 73 00 6f 00 6b 00 6c 00 6f 00 67 00 73 00 } //01 00 
		$a_01_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2d 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //01 00 
		$a_01_2 = {5c 00 6d 00 73 00 6f 00 6c 00 6f 00 67 00 73 00 } //01 00 
		$a_01_3 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } //01 00 
		$a_01_4 = {57 52 4b 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 1d 
	condition:
		any of ($a_*)
 
}