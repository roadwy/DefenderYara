
rule Trojan_Win64_Latrodectus_PH_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 ca 48 b8 cd cc cc cc cc cc cc cc 44 03 d6 48 f7 e1 48 c1 ea 04 48 8d ?? 92 48 c1 e0 ?? 48 2b c8 8a 44 0c ?? 43 32 04 0b 41 88 01 4c 03 ce 45 3b d7 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Latrodectus_PH_MTB_2{
	meta:
		description = "Trojan:Win64/Latrodectus.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 b9 06 00 00 00 90 13 83 c1 02 48 f7 f1 90 13 48 8b c2 48 8b 4c 24 ?? 90 13 0f b6 44 01 ?? 8b 8c 24 ?? 00 00 00 90 13 33 c8 8b c1 90 13 48 63 4c 24 ?? 48 8b 54 24 ?? 90 13 88 04 0a 90 13 8b 44 24 ?? 90 13 ff c0 89 44 24 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}