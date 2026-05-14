
rule Ransom_Win32_HiddenTears_ARR_MTB{
	meta:
		description = "Ransom:Win32/HiddenTears.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 02 00 00 "
		
	strings :
		$a_81_0 = {31 41 31 7a 50 31 65 50 35 51 47 65 66 69 32 44 4d 50 54 66 54 4c 35 53 4c 6d 76 37 44 69 76 66 4e 61 } //19 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
		$a_81_1 = {3d 3d 3d 20 52 41 4e 53 4f 4d 20 4e 4f 54 45 } //5 === RANSOM NOTE
	condition:
		((#a_81_0  & 1)*19+(#a_81_1  & 1)*5) >=24
 
}