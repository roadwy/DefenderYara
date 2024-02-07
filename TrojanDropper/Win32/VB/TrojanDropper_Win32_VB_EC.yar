
rule TrojanDropper_Win32_VB_EC{
	meta:
		description = "TrojanDropper:Win32/VB.EC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 75 6e 70 65 4d } //01 00  RunpeM
		$a_00_1 = {72 63 34 00 41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00 
		$a_03_2 = {8b 55 e8 83 c4 28 33 c0 81 fa 08 c5 bb 6c 0f 95 c0 48 68 90 01 02 40 00 89 45 dc eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}