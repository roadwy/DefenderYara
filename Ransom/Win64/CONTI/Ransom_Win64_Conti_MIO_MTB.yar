
rule Ransom_Win64_Conti_MIO_MTB{
	meta:
		description = "Ransom:Win64/Conti.MIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 e8 8b c8 81 f1 78 3b f6 82 80 e2 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0 8b ca d1 e9 8b c1 35 78 3b f6 82 80 e2 ?? 0f 44 c1 49 83 e9 01 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}