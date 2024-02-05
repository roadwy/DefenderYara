
rule TrojanDropper_Win32_FakeAV_DG_MTB{
	meta:
		description = "TrojanDropper:Win32/FakeAV.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 18 8a 54 24 13 30 14 08 40 3b c5 72 f0 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}