
rule Trojan_Win64_LummaC_GTX_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 88 d1 41 80 e1 ?? 44 20 ee 88 5d b4 80 e3 ?? 45 20 ee 41 08 f1 44 08 f3 41 30 d9 8a 5d b4 08 da } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}