
rule Backdoor_BAT_Remcos_GJW_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 38 07 09 6f 90 01 03 0a 07 18 6f 90 01 03 0a 28 90 01 03 06 13 04 07 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 de 24 08 2b cc 06 2b cb 6f 90 01 03 0a 2b c6 0d 2b c5 90 00 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 TripleDESCryptoServiceProvider
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}