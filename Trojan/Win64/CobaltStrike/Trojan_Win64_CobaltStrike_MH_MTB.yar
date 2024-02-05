
rule Trojan_Win64_CobaltStrike_MH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f b6 d1 4d 8d 40 01 33 c2 8b c8 d1 e8 83 e1 01 f7 d9 81 e1 20 83 78 ed 33 c8 8b c1 d1 e9 83 e0 01 f7 d8 25 20 83 78 ed 33 c1 8b c8 d1 e8 } //05 00 
		$a_01_1 = {41 74 6f 6d 4c 64 72 2e 64 6c 6c } //05 00 
		$a_01_2 = {49 6e 69 74 69 61 6c 69 7a 65 41 74 6f 6d 53 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}