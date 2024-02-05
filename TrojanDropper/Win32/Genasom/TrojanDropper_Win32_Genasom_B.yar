
rule TrojanDropper_Win32_Genasom_B{
	meta:
		description = "TrojanDropper:Win32/Genasom.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 2e 65 78 65 90 02 03 e8 90 01 02 ff ff 6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 40 90 00 } //01 00 
		$a_03_1 = {83 c0 04 c1 90 01 01 0d 3d 90 01 02 00 00 72 e8 90 00 } //01 00 
		$a_01_2 = {74 dc 00 00 00 83 c4 04 b8 2e 74 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}