
rule Trojan_BAT_SpySnake_MAR_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {30 35 35 62 39 32 62 35 2d 61 66 63 33 2d 34 36 32 35 2d 61 33 33 66 2d 32 36 65 66 63 36 39 64 30 39 62 37 } //1 055b92b5-afc3-4625-a33f-26efc69d09b7
		$a_01_1 = {53 68 69 74 7a } //1 Shitz
		$a_01_2 = {56 6c 61 6b 52 65 67 69 6f 6e 2e 4d 6f 64 65 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 VlakRegion.Model.Properties.Resources
		$a_01_3 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}