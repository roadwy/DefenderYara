
rule TrojanDropper_Win32_Oficla_T{
	meta:
		description = "TrojanDropper:Win32/Oficla.T,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 04 24 00 00 00 00 ff d0 83 ec 0c } //01 00 
		$a_03_1 = {83 f9 07 7f 15 c1 e1 90 01 01 b8 90 01 04 d3 e8 83 e0 0f ff 24 85 90 00 } //01 00 
		$a_01_2 = {8b 5d 0c 8a 4d 10 d3 eb 8b 55 0c 8b 42 3c 8b 4c 03 78 01 cb } //02 00 
		$a_03_3 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 40 89 04 24 ff 90 01 01 83 ec 1c 90 00 } //02 00 
		$a_03_4 = {89 44 24 04 c7 04 24 00 00 00 00 ff 15 90 01 04 83 ec 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}