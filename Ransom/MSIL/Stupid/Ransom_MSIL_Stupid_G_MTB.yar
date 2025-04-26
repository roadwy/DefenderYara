
rule Ransom_MSIL_Stupid_G_MTB{
	meta:
		description = "Ransom:MSIL/Stupid.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 3 & Del  1
		$a_80_1 = {69 6d 68 61 5f 7a 61 6d 61 6e 69 } //imha_zamani  1
		$a_80_2 = {45 6e 63 72 79 70 74 } //Encrypt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}