
rule Trojan_BAT_SpySnake_MAX_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 44 00 00 00 06 00 00 00 2d } //10
		$a_01_1 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_5 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_6 = {53 6f 6c 64 69 72 65 44 61 74 61 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SoldireData.Properties
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}