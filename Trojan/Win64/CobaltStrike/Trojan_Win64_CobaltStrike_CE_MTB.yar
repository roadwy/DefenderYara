
rule Trojan_Win64_CobaltStrike_CE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b ca 48 ff c2 83 e1 90 01 01 42 8a 0c 31 32 0c 2b 88 0b 48 ff c3 48 ff c8 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 4c 89 ca 48 29 c2 48 8b 45 90 01 01 48 01 d0 0f b6 10 8b 45 90 01 01 01 d0 44 31 c0 88 01 83 45 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_CE_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 02 49 83 c1 20 49 83 c2 20 48 ff c9 41 89 41 e0 41 8b 42 e4 41 89 41 e4 41 8b 42 e8 41 89 41 e8 41 8b 42 ec 41 89 41 ec 41 8b 42 f0 41 89 41 f0 41 8b 42 f4 41 89 41 f4 41 8b 42 f8 41 89 41 f8 41 8b 42 fc 41 89 41 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CE_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c6 89 f1 48 8b 15 90 01 03 00 8b 45 fc 48 98 48 01 d0 89 ca 88 10 83 45 fc 01 eb 90 00 } //2
		$a_03_1 = {89 45 fc 8b 45 fc 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 90 01 03 00 ff d0 48 89 45 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win64_CobaltStrike_CE_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b6 07 4c 8d 44 24 68 48 8b 54 24 60 34 45 4c 63 f6 41 b9 01 00 00 00 49 03 d6 88 44 24 68 49 8b cf 4c 89 64 24 20 } //10
		$a_81_1 = {42 79 70 61 73 73 5f 41 56 2e 70 64 62 } //3 Bypass_AV.pdb
		$a_81_2 = {66 75 63 6b 20 73 61 6e 64 62 6f 78 } //3 fuck sandbox
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}