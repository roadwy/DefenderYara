
rule Ransom_MSIL_CryCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/CryCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {37 00 31 00 32 00 30 00 36 00 35 00 62 00 39 00 2d 00 31 00 37 00 61 00 32 00 2d 00 34 00 30 00 31 00 61 00 2d 00 38 00 31 00 62 00 62 00 2d 00 32 00 34 00 38 00 39 00 30 00 35 00 35 00 65 00 31 00 38 00 33 00 62 00 } //1 712065b9-17a2-401a-81bb-2489055e183b
		$a_01_1 = {24 38 64 37 33 33 62 36 30 2d 38 36 33 31 2d 34 63 34 61 2d 62 64 65 62 2d 38 63 66 30 34 33 38 34 39 32 66 31 } //1 $8d733b60-8631-4c4a-bdeb-8cf0438492f1
		$a_03_2 = {06 02 07 6f [0-04] 7e [0-04] 07 7e [0-04] 8e 69 5d 91 61 28 [0-04] 6f [0-04] 26 07 17 58 0b 07 02 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}