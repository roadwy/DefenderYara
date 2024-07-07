
rule Trojan_BAT_Remcos_PI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 a8 61 00 00 28 13 00 00 0a 28 14 00 00 0a 72 01 00 00 70 28 90 01 03 06 28 90 01 03 06 6f 15 00 00 0a 0a 06 72 19 00 00 70 6f 16 00 00 0a 0b 07 28 17 00 00 0a 0c 7e 01 00 00 04 2d 36 20 00 01 00 00 72 33 00 00 70 14 d0 03 00 00 02 28 18 00 00 0a 17 8d 1a 00 00 01 0d 09 16 16 14 28 19 00 00 0a 90 00 } //1
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}