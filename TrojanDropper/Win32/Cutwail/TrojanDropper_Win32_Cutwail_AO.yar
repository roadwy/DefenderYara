
rule TrojanDropper_Win32_Cutwail_AO{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 82 90 01 04 38 08 74 01 40 56 ff d0 90 02 0a 81 ea 90 01 02 ff bf 90 00 } //01 00 
		$a_01_1 = {01 55 f8 31 03 83 e9 04 7e 14 03 45 f8 } //01 00 
		$a_01_2 = {43 61 6e 63 65 6c 49 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}