
rule Trojan_BAT_QuasarRat_SIPM_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.SIPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 72 86 e5 84 70 28 03 00 00 0a 0b 72 e0 e5 84 70 28 03 00 00 0a 0c 28 04 00 00 0a 0d 09 07 6f 05 00 00 0a 09 } //2
		$a_01_1 = {11 06 06 16 06 8e 69 6f 0b 00 00 0a 11 06 6f 0c 00 00 0a 11 05 6f 0d 00 00 0a 28 0e 00 00 0a 6f 0f 00 00 0a 14 14 6f 10 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}