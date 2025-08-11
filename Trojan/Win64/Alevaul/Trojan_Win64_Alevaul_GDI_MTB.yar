
rule Trojan_Win64_Alevaul_GDI_MTB{
	meta:
		description = "Trojan:Win64/Alevaul.GDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 99 5c 69 a4 f2 ?? ?? ?? ?? 37 7b 00 22 58 00 b2 } //5
		$a_03_1 = {48 8d 5c 24 ?? 49 83 f8 10 48 0f 43 5c 24 ?? 48 ff c1 e8 ?? ?? ?? ?? 4c 8b d8 48 8b d0 48 2b d3 0f b6 0b 88 0c 1a 48 8d 5b ?? 84 c9 ?? ?? 44 8b d7 41 0f b7 5f ?? 48 85 db } //5
		$a_03_2 = {49 03 f9 49 03 d1 3b c0 75 30 33 c9 8a 1a 84 db ?? ?? d1 c1 69 c1 f2 6d 00 00 80 fb 61 0f b6 cb 89 44 24 20 8d 43 e0 0f b6 c0 0f 43 c8 30 4c 24 20 8b 4c 24 20 48 ff c2 } //10
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*10) >=10
 
}