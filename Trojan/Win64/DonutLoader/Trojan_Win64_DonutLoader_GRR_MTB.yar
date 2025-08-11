
rule Trojan_Win64_DonutLoader_GRR_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.GRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 01 c2 0f b6 d2 44 29 c2 41 89 d3 48 63 d2 44 0f b6 04 14 46 88 04 14 88 0c 14 42 02 0c 14 0f b6 c9 0f b6 14 0c 30 13 48 83 c3 01 49 39 d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}