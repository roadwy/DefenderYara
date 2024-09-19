
rule Trojan_BAT_Androm_NB_MTB{
	meta:
		description = "Trojan:BAT/Androm.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {07 06 8e 69 17 58 11 06 9e 11 06 06 16 95 61 } //5
		$a_81_1 = {54 65 78 74 46 72 6f 6d } //1 TextFrom
		$a_81_2 = {65 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 encryptedData
		$a_81_3 = {53 68 6f 77 50 61 69 72 73 } //1 ShowPairs
		$a_81_4 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_81_5 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 54 6f 55 69 6e 74 41 72 72 61 79 } //1 ConvertStringToUintArray
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}