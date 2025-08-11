
rule Trojan_Win64_LummaC_PGLF_MTB{
	meta:
		description = "Trojan:Win64/LummaC.PGLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 01 24 00 41 80 e4 ?? 45 08 ef 44 08 e0 41 30 c7 41 80 f7 ?? 88 d8 44 30 f8 20 d8 41 88 ff 41 20 c7 40 30 c7 41 08 ff 40 88 f0 34 ff 24 01 44 88 f7 40 80 f7 ?? 41 88 f4 41 20 fc 45 88 f5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}