
rule TrojanDropper_Win32_Jushed_AS_MTB{
	meta:
		description = "TrojanDropper:Win32/Jushed.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 17 83 c7 04 ba 90 01 04 8b 01 03 d0 83 f0 90 01 01 33 c2 8b 11 83 c1 04 a9 90 00 } //01 00 
		$a_00_1 = {6a 75 73 63 68 65 64 2e 65 78 65 } //01 00 
		$a_00_2 = {57 6f 69 74 41 74 64 44 63 79 65 6e 73 65 72 47 69 77 72 6f } //01 00 
		$a_00_3 = {56 6d 66 61 6e 74 75 6e 6d 6f 65 6c 49 72 69 47 6f 65 6f 74 41 } //00 00 
	condition:
		any of ($a_*)
 
}