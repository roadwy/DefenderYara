
rule Trojan_Win64_LummaC_PGT_MTB{
	meta:
		description = "Trojan:Win64/LummaC.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 c3 41 80 e3 6e 80 e2 91 44 08 da 08 d8 80 e3 6e 80 e1 91 08 d9 30 d1 f6 d0 08 c8 48 8b 8d 30 02 00 00 41 88 44 0a 01 48 8b 85 ?? ?? ?? ?? 48 8b 85 30 02 00 00 48 8b 85 30 02 00 00 bb 16 ca 0c 55 81 fb 86 2f 0b d3 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}