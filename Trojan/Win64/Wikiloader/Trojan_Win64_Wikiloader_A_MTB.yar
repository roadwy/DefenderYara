
rule Trojan_Win64_Wikiloader_A_MTB{
	meta:
		description = "Trojan:Win64/Wikiloader.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 5d f8 4d 31 c0 49 c7 c2 33 00 00 00 49 83 c2 09 46 8b 04 13 50 48 31 c0 48 ff c0 48 85 c0 74 78 58 } //1
		$a_01_1 = {66 8b 0c 4e 48 31 f6 49 c7 c2 0d 00 00 00 49 83 c2 0f 43 8b 34 10 48 01 de 48 31 d2 52 48 31 d2 48 85 d2 } //1
		$a_01_2 = {42 00 61 00 73 00 65 00 36 00 34 00 20 00 45 00 6e 00 63 00 6f 00 64 00 65 00 } //1 Base64 Encode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}