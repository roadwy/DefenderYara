
rule Trojan_Win64_IcedID_MAZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 2b c8 83 e9 90 01 01 48 8b 94 24 90 01 04 8b 84 02 90 01 04 33 c1 b9 04 00 00 00 48 6b c9 00 48 8b 94 24 90 01 04 89 84 0a 90 01 04 b8 04 00 00 00 48 6b c0 00 b9 04 00 00 00 48 6b c9 01 48 8b 94 24 90 01 04 4c 8b 84 24 90 01 04 45 8b 40 3c 8b 4c 0a 7c 41 2b c8 48 8b 94 24 90 01 04 8b 84 02 90 01 04 0f af c1 b9 04 00 00 00 48 6b c9 00 48 8b 94 24 90 01 04 89 84 0a 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MAZ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 69 64 61 74 61 00 00 00 02 00 00 00 c0 00 00 00 02 00 00 00 96 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 68 79 74 00 00 00 00 5d 51 00 00 00 d0 00 00 00 52 00 00 00 98 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 74 72 65 } //01 00 
		$a_01_1 = {42 58 65 53 6b 49 34 64 35 75 } //01 00  BXeSkI4d5u
		$a_01_2 = {45 46 65 73 6e 78 75 56 } //01 00  EFesnxuV
		$a_01_3 = {48 37 47 70 30 42 30 34 } //01 00  H7Gp0B04
		$a_01_4 = {4b 36 66 76 63 67 52 4c 4d 5a } //01 00  K6fvcgRLMZ
		$a_01_5 = {55 39 6d 55 35 46 72 56 42 65 } //00 00  U9mU5FrVBe
	condition:
		any of ($a_*)
 
}