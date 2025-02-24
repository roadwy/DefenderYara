
rule Trojan_Win64_LummaC_YAN_MTB{
	meta:
		description = "Trojan:Win64/LummaC.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 58 44 30 24 0f 49 31 cc 48 ff c1 48 89 c8 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}