
rule Trojan_Win64_LummaC_GA_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 03 c8 8b d1 89 50 20 8b c5 99 f7 f9 8d a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}