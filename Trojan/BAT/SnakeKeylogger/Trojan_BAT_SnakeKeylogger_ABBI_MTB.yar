
rule Trojan_BAT_SnakeKeylogger_ABBI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 1c 00 00 04 6f 3a 00 00 0a 02 16 02 8e 69 6f 3b 00 00 0a 0a 2b 00 06 2a } //3
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {53 00 68 00 74 00 6f 00 6f 00 63 00 6b 00 69 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Shtoockie.Properties.Resources
		$a_01_4 = {48 00 65 00 6c 00 70 00 65 00 72 00 5f 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 } //1 Helper_Classes
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}