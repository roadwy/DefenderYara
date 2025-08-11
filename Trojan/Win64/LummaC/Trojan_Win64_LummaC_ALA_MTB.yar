
rule Trojan_Win64_LummaC_ALA_MTB{
	meta:
		description = "Trojan:Win64/LummaC.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c8 0f b6 01 43 88 04 08 44 88 11 43 0f b6 0c 08 49 03 ca 0f b6 c1 0f b6 8c 04 00 01 00 00 30 0f 48 ff c7 49 83 eb 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}