
rule Trojan_Win64_BigpipeLoader_RPZ_MTB{
	meta:
		description = "Trojan:Win64/BigpipeLoader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 13 4c 8d 4c 24 40 48 83 64 24 20 00 44 8b c7 48 8b cd ff 15 ?? ?? ?? ?? 85 c0 74 0d 8b 4c 24 40 48 01 0b 01 0e 2b f9 75 d5 } //1
		$a_03_1 = {4c 8d 4d ef 4c 89 6c 24 20 44 8b c7 48 8b d3 49 8b ce ff 15 ?? ?? ?? ?? 85 c0 74 0c 8b 4d ef 48 03 d9 03 f1 2b f9 75 d8 } //1
		$a_03_2 = {4c 8d 4d ef 4c 89 6c 24 20 44 8b c3 49 8b d7 48 8b ce ff 15 ?? ?? ?? ?? 85 c0 74 0c 8b 4d ef 4c 03 f9 03 f9 2b d9 75 d8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}