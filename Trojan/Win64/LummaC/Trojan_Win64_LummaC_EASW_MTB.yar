
rule Trojan_Win64_LummaC_EASW_MTB{
	meta:
		description = "Trojan:Win64/LummaC.EASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 09 eb 48 f7 d0 48 31 c3 48 f7 d3 48 21 c3 48 89 5c 24 58 b8 3a ad fd d5 3d 3a 98 52 e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}