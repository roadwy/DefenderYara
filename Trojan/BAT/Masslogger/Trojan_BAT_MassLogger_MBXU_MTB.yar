
rule Trojan_BAT_MassLogger_MBXU_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //5 CreateInstance
		$a_01_1 = {44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 65 00 72 00 54 00 6f 00 6f 00 6c 00 73 00 2e 00 51 00 75 00 69 00 63 00 6b 00 46 00 6f 00 72 00 6d 00 73 00 } //4 DeveloperTools.QuickForms
		$a_01_2 = {53 70 6c 69 74 } //3 Split
		$a_01_3 = {47 65 74 50 69 78 65 6c } //2 GetPixel
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=14
 
}