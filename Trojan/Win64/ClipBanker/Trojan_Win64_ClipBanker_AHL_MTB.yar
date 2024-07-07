
rule Trojan_Win64_ClipBanker_AHL_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {31 06 01 1e 48 83 c6 04 ff c9 eb 90 0a 0f 00 85 c9 74 90 00 } //1
		$a_03_1 = {8a 06 48 ff c6 88 07 48 ff c7 bb 02 00 00 00 00 d2 75 90 02 09 73 90 00 } //1
		$a_03_2 = {8b 45 f4 ff c0 89 45 f4 81 7d f4 80 00 00 00 74 90 01 01 8b 45 10 89 83 c3 18 33 18 ff 45 10 48 ff c3 eb 90 00 } //1
		$a_01_3 = {fe 0f 48 ff c7 ff c9 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}