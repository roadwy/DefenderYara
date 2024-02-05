
rule TrojanDropper_Win32_Lucuis_A{
	meta:
		description = "TrojanDropper:Win32/Lucuis.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {37 38 39 65 72 69 63 30 31 32 } //01 00 
		$a_03_1 = {8b 44 24 0c 56 8d 70 3f 8b 44 24 08 83 e6 c0 85 c0 0f 84 90 01 02 00 00 8b 44 24 0c 85 c0 0f 84 90 01 02 00 00 8b 44 24 14 85 c0 90 03 07 04 0f 84 90 01 02 00 00 74 90 01 01 85 f6 74 90 01 01 8b 4c 24 18 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}