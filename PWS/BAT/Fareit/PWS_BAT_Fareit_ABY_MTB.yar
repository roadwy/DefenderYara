
rule PWS_BAT_Fareit_ABY_MTB{
	meta:
		description = "PWS:BAT/Fareit.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 d5 02 e8 09 03 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 26 00 00 00 12 00 00 00 39 00 00 00 66 02 00 00 17 00 00 00 } //4
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {43 6f 6e 66 75 73 65 72 } //1 Confuser
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}