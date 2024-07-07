
rule Trojan_Win64_Emotet_PAH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 4c 24 24 8b 54 24 20 2b d1 8b ca 03 4c 24 24 48 63 c9 48 8b 54 24 40 88 04 0a eb 94 48 8d 0d ce 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Emotet_PAH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa 02 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 01 c0 29 c1 89 ca 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 04 01 83 85 90 01 04 01 8b 85 90 01 04 3b 85 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}