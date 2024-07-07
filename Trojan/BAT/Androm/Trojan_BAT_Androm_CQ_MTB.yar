
rule Trojan_BAT_Androm_CQ_MTB{
	meta:
		description = "Trojan:BAT/Androm.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 f7 02 0f 70 28 3e 00 00 0a 11 05 28 3f 00 00 0a 13 0d 11 0d 28 40 00 00 0a 26 11 0d 07 7b 06 00 00 04 72 07 03 0f 70 28 41 00 00 0a 13 0e 11 0e 28 42 00 00 0a 2d 2d } //1
		$a_01_1 = {11 0e 28 43 00 00 0a 25 11 0b 16 11 0b 8e 69 6f 44 00 00 0a 6f 2c 00 00 0a 11 0e 14 1a 28 26 00 00 06 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}