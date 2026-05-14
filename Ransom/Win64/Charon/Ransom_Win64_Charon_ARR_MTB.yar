
rule Ransom_Win64_Charon_ARR_MTB{
	meta:
		description = "Ransom:Win64/Charon.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d1 8b ca 03 c1 33 44 24 ?? 8b 0c 24 83 c1 } //12
		$a_03_1 = {33 c8 8b c1 8b 8c 24 ?? ?? ?? ?? 03 c8 8b c1 8b 0c 24 83 c1 ?? 8b c9 48 8b 94 24 } //8
	condition:
		((#a_03_0  & 1)*12+(#a_03_1  & 1)*8) >=20
 
}