
rule Trojan_Win64_PuppyRAT_A_MTB{
	meta:
		description = "Trojan:Win64/PuppyRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 48 ff c1 41 33 c0 44 8b c0 8a 01 45 69 c0 } //02 00 
		$a_01_1 = {0f b6 c0 33 c2 8b d0 69 d2 } //02 00 
		$a_01_2 = {41 0f b6 00 ff c9 49 ff c0 } //00 00 
	condition:
		any of ($a_*)
 
}