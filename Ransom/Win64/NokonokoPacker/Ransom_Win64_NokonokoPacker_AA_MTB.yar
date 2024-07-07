
rule Ransom_Win64_NokonokoPacker_AA_MTB{
	meta:
		description = "Ransom:Win64/NokonokoPacker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 31 04 09 49 83 c1 04 8b 83 90 01 04 01 43 90 01 01 8b 83 90 01 04 01 83 90 01 04 49 81 f9 90 01 04 90 13 8b 83 90 01 04 2b 43 90 01 01 48 8b 8b 90 01 04 05 90 01 04 01 83 90 01 04 8b 83 90 01 04 33 83 90 01 04 35 90 01 04 89 83 90 01 04 8b 43 90 01 01 42 31 04 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}