
rule Ransom_Win64_Conti_GHJ_MTB{
	meta:
		description = "Ransom:Win64/Conti.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 c0 0f 69 c8 93 35 87 1b 33 f9 c1 c7 0d 81 c7 14 af dd fa 8d 3c bf 49 83 c0 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}