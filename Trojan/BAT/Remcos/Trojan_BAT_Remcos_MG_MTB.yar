
rule Trojan_BAT_Remcos_MG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 b7 b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 fb 00 00 00 4c 00 00 00 98 00 00 00 d5 } //10
		$a_81_1 = {43 6f 72 74 65 7a 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Cortez.Properties.Resources
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}