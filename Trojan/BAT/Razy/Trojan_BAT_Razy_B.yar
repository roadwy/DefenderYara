
rule Trojan_BAT_Razy_B{
	meta:
		description = "Trojan:BAT/Razy.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 3c 00 00 0a 0a 02 16 28 45 00 00 0a 0b 06 02 1a 02 8e 69 1a 59 6f 3e 00 00 0a 07 8d 0c 00 00 01 0c 06 16 6a 6f 40 00 00 0a 06 16 73 46 00 00 0a 0d 09 08 16 08 8e 69 6f 42 00 00 0a 26 08 2a } //1
		$a_01_1 = {02 7b 09 00 00 04 61 20 20 a7 00 00 58 d1 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}