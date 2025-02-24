
rule Trojan_Win64_CobaltStrike_GZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 72 69 64 69 70 69 76 6d 73 6e 73 75 70 75 73 } //1 bridipivmsnsupus
		$a_01_1 = {47 4f 4d 41 58 50 52 4f 43 53 } //1 GOMAXPROCS
		$a_01_2 = {4f 54 54 4f 74 74 63 66 77 4f 46 46 77 4f 46 32 50 4b } //1 OTTOttcfwOFFwOF2PK
		$a_01_3 = {20 47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1  Go buildinf:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_CobaltStrike_GZ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 03 d0 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 ?? 41 8a c0 41 ff c0 2a c1 04 ?? 41 30 01 49 ff c1 41 83 f8 } //1
		$a_03_1 = {8b c3 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 44 03 c7 4c 03 cf 41 83 f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}