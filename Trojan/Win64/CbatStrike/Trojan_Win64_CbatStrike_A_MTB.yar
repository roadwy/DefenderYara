
rule Trojan_Win64_CbatStrike_A_MTB{
	meta:
		description = "Trojan:Win64/CbatStrike.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8b 54 24 24 41 0f b6 cc 44 0a e6 f6 d1 40 0f b6 c6 48 83 c5 01 f6 d0 be 04 00 00 00 0a c8 41 22 cc 49 83 ed 01 88 4d ff 8b 4c 24 20 0f 85 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {c7 44 24 28 00 00 00 00 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 44 8b c5 33 d2 41 ff d4 48 8b f8 44 8b cd 4c 8b c0 48 8b d6 48 8b 0d 90 01 04 41 ff d5 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}