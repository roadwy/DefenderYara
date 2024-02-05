
rule TrojanDropper_Win32_Oficla_I{
	meta:
		description = "TrojanDropper:Win32/Oficla.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c1 01 81 f9 00 08 00 00 19 c0 83 c2 01 21 c1 83 ad 90 01 04 01 90 00 } //01 00 
		$a_03_1 = {31 c1 01 d2 75 f6 8b 9d 90 01 04 83 c7 01 39 bd 90 01 04 89 0b 0f 84 90 01 04 83 c3 04 89 9d 90 01 04 eb af 90 00 } //01 00 
		$a_03_2 = {89 44 24 0c 8b 85 90 01 04 89 4c 24 04 c7 44 24 10 00 00 00 00 89 14 24 89 44 24 08 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}