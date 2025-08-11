
rule Trojan_Win64_LummaC_GF_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 c1 40 30 f1 20 c1 88 d0 20 c8 30 ca 08 d0 88 c1 80 f1 ff 80 e1 01 8a 55 e2 } //3
		$a_01_1 = {20 c8 41 30 cb 44 08 d8 44 88 c1 80 f1 ff 88 c2 20 ca } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}