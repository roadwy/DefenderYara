
rule Ransom_Win64_BlackBasta_MP_MTB{
	meta:
		description = "Ransom:Win64/BlackBasta.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 88 4b 70 c1 e8 08 88 43 71 8b c1 c1 e8 10 88 43 72 c1 e9 18 88 4b 73 8b 4c 24 54 8b c1 88 4b 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}