
rule Trojan_Win64_Emotet_BH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c9 0f b6 0c 01 42 32 8c 1c a2 00 00 00 49 83 c3 03 43 88 4c 11 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_BH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 63 ca 4c 8b 55 90 01 01 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d 90 01 04 48 63 75 90 01 01 45 88 1c 31 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 e9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Emotet_BH_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.BH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 f7 e7 8b cf ff c7 c1 ea 05 6b c2 2f 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ff 41 88 40 ff 41 3b fc 72 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}