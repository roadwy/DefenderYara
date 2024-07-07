
rule Trojan_BAT_Bladabindi_DL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 19 2b 1a 18 2d 1a 26 26 2b 1d 6f 90 01 03 0a 28 90 01 03 0a 0d 1d 2c f0 de 2a 07 2b e4 08 2b e3 6f 90 01 03 0a 2b e1 08 2b e0 16 2d 0c 19 2c 09 08 2c 06 08 6f 90 01 03 0a dc 90 00 } //10
		$a_81_1 = {52 65 61 64 65 72 31 } //1 Reader1
		$a_81_2 = {52 65 61 64 65 72 32 } //1 Reader2
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}