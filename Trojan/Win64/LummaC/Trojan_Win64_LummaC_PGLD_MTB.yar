
rule Trojan_Win64_LummaC_PGLD_MTB{
	meta:
		description = "Trojan:Win64/LummaC.PGLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 88 f8 34 01 24 00 41 80 e4 ?? 45 08 ee 44 08 e0 41 30 c6 41 80 f6 ff 40 88 f8 34 00 41 88 fc 41 80 f4 ?? 41 08 c6 41 80 cc ?? 41 80 f6 ff 45 20 e6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}