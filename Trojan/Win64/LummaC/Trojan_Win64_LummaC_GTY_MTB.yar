
rule Trojan_Win64_LummaC_GTY_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 08 e6 45 08 fd 45 30 ee 45 88 df 41 80 f7 ?? 41 88 dc 41 80 f4 ?? 41 88 fd 41 80 f5 ?? 45 88 fa 41 80 e2 ?? 45 20 eb 44 88 a5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}