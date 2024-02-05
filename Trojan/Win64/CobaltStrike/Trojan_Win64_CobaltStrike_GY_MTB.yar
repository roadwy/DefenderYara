
rule Trojan_Win64_CobaltStrike_GY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 41 f7 e0 c1 ea 04 0f be c2 6b c8 90 01 01 41 8a c0 2a c1 04 90 01 01 41 30 01 44 03 c3 4c 03 cb 41 83 f8 0d 7c dc 90 00 } //01 00 
		$a_03_1 = {45 33 c0 4c 8d 4c 24 20 b8 90 01 04 41 f7 e0 c1 ea 04 0f be c2 6b c8 90 01 01 41 8a c0 41 ff c0 2a c1 04 90 01 01 41 30 01 49 ff c1 41 83 f8 18 7c d9 90 00 } //01 00 
		$a_03_2 = {4c 8d 4c 24 50 be 90 01 04 41 8d 5f 01 8b c6 41 f7 e0 c1 ea 90 01 01 0f be c2 6b c8 90 01 01 41 8a c0 2a c1 04 90 01 01 41 30 01 44 03 c3 4c 03 cb 41 83 f8 15 7c dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}