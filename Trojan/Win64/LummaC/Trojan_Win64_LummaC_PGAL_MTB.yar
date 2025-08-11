
rule Trojan_Win64_LummaC_PGAL_MTB{
	meta:
		description = "Trojan:Win64/LummaC.PGAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c6 44 0f af ce 41 83 e1 01 41 83 f9 00 0f 94 c3 80 e3 01 88 5d f6 41 83 fa 0a 0f 9c c3 80 e3 01 88 5d f7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}