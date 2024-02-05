
rule Trojan_Win64_Cobaltstrike_DX_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 2b 05 90 01 04 2b 05 90 01 04 2b 05 90 01 04 2b 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 48 63 c8 48 8b 44 24 50 0f b6 0c 08 48 8b 44 24 58 44 0f b6 24 10 44 33 e1 8b 2d 90 01 04 0f af 2d 90 01 04 8b 35 90 00 } //01 00 
		$a_81_1 = {66 75 2b 6d 65 4e 21 5f 44 7a 58 46 21 46 44 42 4d 55 67 38 5a 2a 33 7a 62 49 34 3c 69 2b 79 5a 3c 44 6e 79 39 61 77 6f 29 23 53 64 } //00 00 
	condition:
		any of ($a_*)
 
}