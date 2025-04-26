
rule Trojan_BAT_Remcos_EL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 0e 00 00 "
		
	strings :
		$a_81_0 = {45 78 63 65 70 74 69 6f 6e 44 69 73 70 61 74 63 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //20 ExceptionDispatch.Properties.Resources
		$a_81_1 = {47 72 61 70 68 69 63 73 55 74 69 6c 69 74 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //20 GraphicsUtility.Properties.Resources
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_4 = {4d 61 74 72 69 78 33 78 33 } //1 Matrix3x3
		$a_81_5 = {41 45 53 5f 44 65 63 72 79 70 74 } //1 AES_Decrypt
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_7 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_8 = {43 6f 6e 63 61 74 } //1 Concat
		$a_81_9 = {52 6f 74 61 74 65 58 } //1 RotateX
		$a_81_10 = {52 6f 74 61 74 65 59 } //1 RotateY
		$a_81_11 = {52 6f 74 61 74 65 5a } //1 RotateZ
		$a_81_12 = {46 6c 6f 72 61 } //1 Flora
		$a_81_13 = {43 72 65 61 74 65 46 69 6c 65 } //1 CreateFile
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=32
 
}