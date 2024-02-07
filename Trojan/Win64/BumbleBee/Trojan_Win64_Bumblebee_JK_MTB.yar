
rule Trojan_Win64_Bumblebee_JK_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 41 b8 00 30 00 00 8b 53 90 01 01 44 8d 49 90 01 01 ff 15 90 00 } //01 00 
		$a_03_1 = {8b 82 94 00 00 00 35 90 01 04 2b c8 48 8d 05 90 01 04 81 f1 90 01 04 48 89 42 90 01 01 89 4a 90 00 } //01 00 
		$a_00_2 = {56 49 44 52 56 53 74 61 74 65 } //00 00  VIDRVState
	condition:
		any of ($a_*)
 
}