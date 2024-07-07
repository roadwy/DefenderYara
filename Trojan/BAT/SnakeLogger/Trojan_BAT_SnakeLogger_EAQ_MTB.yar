
rule Trojan_BAT_SnakeLogger_EAQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.EAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 15 2d 22 26 28 90 01 01 01 00 0a 06 6f 90 01 01 01 00 0a 28 90 01 01 00 00 0a 16 2c 11 26 02 07 28 90 01 01 01 00 06 1e 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c9 90 00 } //3
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 33 00 34 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 WindowsFormsApp34.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}