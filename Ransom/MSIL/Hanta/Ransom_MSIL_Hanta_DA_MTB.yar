
rule Ransom_MSIL_Hanta_DA_MTB{
	meta:
		description = "Ransom:MSIL/Hanta.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 61 6e 74 61 5f 32 5f 30 5f 6f 66 66 6c 69 6e 65 } //1 hanta_2_0_offline
		$a_81_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_2 = {67 65 74 5f 49 73 41 6c 69 76 65 } //1 get_IsAlive
		$a_81_3 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}