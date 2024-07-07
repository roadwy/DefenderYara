
rule Trojan_Win64_CobaltStrike_BNN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {35 78 81 b2 db 89 05 45 df 03 00 0f b7 05 3a df 03 00 48 b9 90 02 09 48 03 c1 48 89 05 36 df 03 00 8b 04 24 89 44 24 10 e9 65 f9 ff ff 90 00 } //1
		$a_01_1 = {35 3d dc 00 00 66 89 05 a9 de 03 00 0f b6 05 9a de 03 00 35 8a 00 00 00 88 05 8f de 03 00 0f b7 05 8c de 03 00 25 be 35 00 00 66 89 05 84 de 03 00 0f b7 05 7d de 03 00 25 e7 5a 53 a1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}