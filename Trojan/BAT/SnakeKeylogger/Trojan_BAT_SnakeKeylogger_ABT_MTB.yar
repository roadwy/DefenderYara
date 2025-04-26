
rule Trojan_BAT_SnakeKeylogger_ABT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 09 16 11 04 2b 15 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 02 2b 09 2b e4 6f ?? ?? ?? 0a 2b e4 07 6f ?? ?? ?? 0a 13 05 de 17 } //4
		$a_03_1 = {72 33 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2a } //4
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}
rule Trojan_BAT_SnakeKeylogger_ABT_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {03 28 70 00 00 06 26 7e 6b 00 00 04 18 6f bf 00 00 0a 00 02 28 72 00 00 06 0a 2b 00 06 2a } //2
		$a_01_1 = {7e 6b 00 00 04 6f bc 00 00 0a 02 16 02 8e 69 6f bd 00 00 0a 0a 2b 00 06 2a } //2
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {48 00 65 00 6c 00 70 00 65 00 72 00 5f 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 } //1 Helper_Classes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}