
rule Trojan_Win64_Cobaltstrike_DY_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ca 03 c1 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 2b c1 2b 05 90 01 04 48 63 c8 48 8b 84 24 90 01 04 0f b6 0c 08 48 8b 84 24 90 01 04 42 0f b6 04 00 33 c1 89 44 24 14 8b 05 90 01 04 0f af 05 90 01 04 89 44 24 18 8b 05 90 01 04 0f af 05 90 00 } //01 00 
		$a_81_1 = {4f 23 33 37 48 57 5e 24 4c 28 6e 2b 47 77 56 65 47 28 6d 48 66 4d 75 21 28 59 51 35 79 29 6e 36 79 42 28 45 6a 5f 6e 61 48 41 55 64 3e } //00 00 
	condition:
		any of ($a_*)
 
}