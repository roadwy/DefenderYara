
rule Trojan_Win64_Emotet_PBH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 90 02 06 0f b6 04 01 8b 4c 24 90 01 01 33 c8 8b c1 8b 4c 24 90 01 01 8b 54 24 90 01 01 2b d1 8b ca 03 4c 24 90 01 01 48 63 c9 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Emotet_PBH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 d1 48 8b ca 48 2b 8c 24 90 02 04 48 03 c1 48 89 44 24 90 02 04 48 8b 8c 24 90 02 04 e8 90 00 } //1
		$a_01_1 = {48 47 44 46 5a 46 73 61 74 72 77 35 34 33 34 67 72 68 6a 67 66 48 46 5a 44 72 33 36 67 68 } //1 HGDFZFsatrw5434grhjgfHFZDr36gh
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}