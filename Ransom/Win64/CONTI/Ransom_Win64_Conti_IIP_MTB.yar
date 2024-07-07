
rule Ransom_Win64_Conti_IIP_MTB{
	meta:
		description = "Ransom:Win64/Conti.IIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 46 88 44 0d b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}