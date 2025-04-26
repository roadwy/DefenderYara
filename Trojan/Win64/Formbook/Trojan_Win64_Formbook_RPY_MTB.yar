
rule Trojan_Win64_Formbook_RPY_MTB{
	meta:
		description = "Trojan:Win64/Formbook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8b 4e 28 44 89 4d ac c7 44 24 20 40 00 00 00 49 8b cd 48 89 4d 80 48 8b d7 48 89 95 78 ff ff ff 44 89 45 8c 41 b9 00 30 00 00 44 89 4d 88 48 8d 8d 50 ff ff ff e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}