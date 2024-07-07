
rule Trojan_Win64_IcedID_GBC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 24 8b c0 48 8b 4c 24 50 8a 04 01 88 44 24 2c 8a 44 24 2c 0f b6 c0 48 8b 4c 24 38 8a 04 01 0f b6 c0 8a 4c 24 20 0f b6 c9 33 c1 8b 4c 24 24 8b c9 88 44 0c 60 8a 44 24 20 fe c0 88 44 24 20 8b 44 24 24 ff c0 89 44 24 24 8b 44 24 24 3d 00 01 00 00 73 02 eb a8 } //10
		$a_01_1 = {48 8b 44 24 48 8a 4c 24 21 88 08 48 8b 44 24 48 48 ff c0 48 89 44 24 48 8b 44 24 28 ff c8 89 44 24 28 83 7c 24 28 00 74 02 eb 89 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}