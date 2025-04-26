
rule Trojan_Win64_PrivateLoader_RPZ_MTB{
	meta:
		description = "Trojan:Win64/PrivateLoader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 33 c9 8b 54 24 6c 41 c7 c0 00 10 00 00 41 c7 c1 40 00 00 00 48 8b 44 24 40 ff d0 48 89 c3 48 89 d9 48 8d 96 fb 5b 04 00 44 8b 44 24 6c 41 81 e8 fb 5b 04 00 48 8b 44 24 38 ff d0 48 89 f9 48 8b 44 24 48 ff d0 4c 89 e9 48 8b 44 24 48 ff d0 48 89 de ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}