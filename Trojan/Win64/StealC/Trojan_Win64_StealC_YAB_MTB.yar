
rule Trojan_Win64_StealC_YAB_MTB{
	meta:
		description = "Trojan:Win64/StealC.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 48 89 84 24 90 01 04 48 8b 84 24 90 01 04 8b 8c 24 90 01 04 8b 00 33 c1 48 8b 8c 24 90 01 04 89 01 8b 44 24 5c 83 c0 04 89 44 24 90 00 } //05 00 
		$a_03_1 = {ff c0 89 44 24 28 8b 44 24 24 39 44 24 28 73 33 48 8b 84 24 90 01 04 ff 50 10 48 98 33 d2 b9 1a 00 00 00 48 f7 f1 48 8b c2 66 0f be 44 04 58 48 63 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}