
rule TrojanDropper_Win32_Bamital_D{
	meta:
		description = "TrojanDropper:Win32/Bamital.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 70 6c 68 6c 70 00 } //01 00 
		$a_00_1 = {5c 00 52 00 50 00 43 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 73 00 70 00 6f 00 6f 00 6c 00 73 00 73 00 00 00 } //01 00 
		$a_03_2 = {8b 75 0c 80 3e e9 75 18 e8 90 01 04 83 f8 05 75 07 ba 0a 00 00 00 eb 0c e9 a0 00 00 00 eb 05 ba 05 00 00 00 bb 00 00 00 00 8b 75 0c eb 90 01 01 e8 90 01 04 83 f8 ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}