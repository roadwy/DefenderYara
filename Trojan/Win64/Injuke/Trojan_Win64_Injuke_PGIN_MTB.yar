
rule Trojan_Win64_Injuke_PGIN_MTB{
	meta:
		description = "Trojan:Win64/Injuke.PGIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 3b 44 24 18 0f 83 47 00 00 00 48 8b 44 24 20 48 89 04 24 48 8b 44 24 08 31 c9 89 ca 48 f7 74 24 28 48 8b 04 24 44 0f b6 04 10 48 8b 44 24 10 48 8b 4c 24 08 0f b6 14 08 44 31 c2 88 14 08 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 e9 } //5
		$a_80_1 = {5f 53 63 72 65 65 6e 43 6f 6e 6e 65 63 74 } //_ScreenConnect  5
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}