
rule TrojanDropper_Win32_Nekav_A{
	meta:
		description = "TrojanDropper:Win32/Nekav.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 18 80 7c 1e ff 2e 75 11 57 b9 ff ff ff 7f 8b d3 8b c6 e8 90 01 2f 8b 18 0f b6 1c 13 33 d9 90 00 } //01 00 
		$a_03_1 = {6c 34 31 46 72 44 00 90 01 09 6c 38 6c 55 58 44 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}