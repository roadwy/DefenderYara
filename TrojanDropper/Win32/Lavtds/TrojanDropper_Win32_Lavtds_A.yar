
rule TrojanDropper_Win32_Lavtds_A{
	meta:
		description = "TrojanDropper:Win32/Lavtds.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c1 04 35 98 98 74 92 81 f9 c8 2c 00 00 89 84 2a 90 01 04 89 ca 75 e1 90 00 } //01 00 
		$a_03_1 = {c1 27 72 66 90 01 03 41 30 29 18 e8 90 01 04 a3 90 01 04 89 90 01 02 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}