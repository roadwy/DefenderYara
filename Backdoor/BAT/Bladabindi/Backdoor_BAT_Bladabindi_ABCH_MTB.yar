
rule Backdoor_BAT_Bladabindi_ABCH_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ABCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 06 07 6f 90 01 03 0a 0d 00 02 09 28 90 01 03 06 13 04 de 16 09 2c 07 09 6f 90 01 03 0a 00 dc 90 00 } //2
		$a_03_1 = {0a 0d 07 09 6f 90 01 03 0a 00 08 6f 90 01 03 0a 2d e9 90 0a 17 00 08 6f 90 00 } //1
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 32 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsFormsApp21.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}