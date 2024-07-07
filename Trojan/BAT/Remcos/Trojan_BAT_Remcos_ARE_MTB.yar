
rule Trojan_BAT_Remcos_ARE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 2b f1 0b 2b f8 02 50 06 91 17 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARE_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 26 7e 03 00 00 04 18 6f 42 00 00 0a 00 02 02 02 03 03 03 04 03 04 0e 04 28 08 00 00 06 0a 2b 00 } //1
		$a_01_1 = {7e 04 00 00 04 28 3e 00 00 0a 02 6f 3f 00 00 0a 6f 40 00 00 0a 0a 7e 03 00 00 04 06 25 0b 6f 41 00 00 0a 00 07 0c 2b 00 08 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}