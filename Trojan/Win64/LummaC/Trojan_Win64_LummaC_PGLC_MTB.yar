
rule Trojan_Win64_LummaC_PGLC_MTB{
	meta:
		description = "Trojan:Win64/LummaC.PGLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 01 24 00 41 80 e4 01 45 08 ee 44 08 e0 41 30 c6 41 80 f6 ff 40 88 f8 34 00 41 88 fc 41 80 f4 01 41 08 c6 41 80 cc 01 41 80 f6 ff 45 20 e6 40 88 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}