
rule Trojan_Win64_Rozena_EN_MTB{
	meta:
		description = "Trojan:Win64/Rozena.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 ec 48 8b 4d c8 48 63 d0 8b 45 f0 48 98 48 0f af c3 48 01 ca 48 01 d0 0f b6 10 8b 45 f4 48 63 c8 48 8b 45 c0 48 01 c8 88 10 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win64_Rozena_EN_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 84 24 e0 01 00 00 8b c1 c1 e8 08 88 84 24 e1 01 00 00 8b c1 c1 e8 10 45 8d 41 06 88 84 24 e2 01 00 00 0f b6 44 24 22 88 84 24 e4 01 00 00 0f b7 44 24 22 c1 e9 18 66 c1 e8 08 88 8c 24 e3 01 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}