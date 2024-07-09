
rule Trojan_Win64_Cobaltstrike_DW_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 f8 08 48 c1 f9 08 0f b6 d1 32 84 3a 80 01 04 00 88 46 fe 43 8d 04 3a 99 41 ff c7 f7 fd 48 63 c2 0f b6 8c 83 58 04 00 00 44 32 84 39 80 01 04 00 44 88 46 ff 4d 3b cd 0f } //2
		$a_03_1 = {44 89 64 24 30 4c 8d 4c 24 30 ba 08 00 00 00 44 8d 42 38 49 8b ce ff 15 ?? ?? 02 00 33 c9 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win64_Cobaltstrike_DW_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c1 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 48 63 c8 48 8b 44 24 70 0f b6 0c 08 48 8b 44 24 78 0f b6 04 10 33 c1 89 44 24 14 8b 05 ?? ?? ?? ?? 0f af 05 } //1
		$a_81_1 = {6f 57 68 4f 7a 3f 57 58 75 52 33 67 6a 4c 78 65 6c 6a 43 77 33 54 63 3e 64 49 28 64 5f 76 70 74 4b 64 38 6d 4e 4f 66 57 58 2b 73 48 52 50 78 51 73 55 70 6c 31 48 79 4d 33 3c 67 63 53 } //1 oWhOz?WXuR3gjLxeljCw3Tc>dI(d_vptKd8mNOfWX+sHRPxQsUpl1HyM3<gcS
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}