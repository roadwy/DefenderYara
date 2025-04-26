
rule Trojan_Win64_CobaltStrike_BM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 ff c0 49 63 c8 48 8d 54 24 30 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 09 41 03 ca 0f b6 d1 0f b6 4c 14 30 32 0c 1e 88 0b 48 ff c3 48 83 ed 01 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_BM_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 0c 2b 09 c1 0f c9 41 33 08 0f c9 43 89 4c 32 0c 31 c0 48 8b 94 24 80 00 00 00 48 8b 6c 24 70 48 83 f8 10 74 ?? 8a 0c 02 30 4c 05 00 48 ff c0 eb } //1
		$a_01_1 = {34 42 65 6a 7a 38 74 78 51 2f 72 44 6e 66 } //1 4Bejz8txQ/rDnf
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_BM_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 ?? ?? ?? ?? ?? ?? 48 01 d0 44 0f b6 00 8b 85 ?? ?? ?? ?? 48 63 d0 48 ?? ?? ?? ?? ?? ?? 48 c1 ea ?? 01 c2 c1 fa ?? 89 c1 c1 f9 ?? 29 ca 6b ca ?? 29 c8 89 c2 89 d0 83 c0 ?? 44 89 c1 31 c1 48 ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 98 88 0c 02 83 85 ?? ?? ?? ?? ?? 83 bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}