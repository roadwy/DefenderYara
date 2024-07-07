
rule Trojan_BAT_Remcos_ABGX_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 75 09 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 09 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 40 00 00 0a 26 1f 0f 13 0e 38 39 fe ff ff } //1
		$a_01_1 = {32 31 34 64 61 39 32 32 36 36 36 36 61 31 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 214da9226666a1.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}