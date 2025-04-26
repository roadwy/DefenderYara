
rule Trojan_Win64_LummaC_AA_MTB{
	meta:
		description = "Trojan:Win64/LummaC.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 8b 54 24 18 48 8b 4c 24 08 4c 63 44 24 1c 42 8b 0c 81 4c 63 c1 42 33 14 80 48 63 c9 89 14 88 8b 44 24 1c 83 c0 01 89 44 24 1c e9 bf ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}