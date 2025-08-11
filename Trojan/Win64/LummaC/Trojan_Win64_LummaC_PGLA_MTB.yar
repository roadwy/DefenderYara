
rule Trojan_Win64_LummaC_PGLA_MTB{
	meta:
		description = "Trojan:Win64/LummaC.PGLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 9c c2 89 d3 30 cb 08 ca 80 f2 01 08 da 41 89 d0 41 30 d8 84 d2 b9 ?? ?? ?? ?? 41 0f 45 cc 84 db 41 0f 44 cc 48 89 84 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}