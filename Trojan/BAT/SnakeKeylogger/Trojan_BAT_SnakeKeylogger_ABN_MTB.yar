
rule Trojan_BAT_SnakeKeylogger_ABN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 17 a2 09 09 09 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 42 00 00 00 17 00 00 00 36 00 00 00 8e 00 00 00 } //4
		$a_01_1 = {67 65 74 57 65 62 52 65 73 70 6f 6e 73 65 } //1 getWebResponse
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {53 68 69 74 7a } //1 Shitz
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}