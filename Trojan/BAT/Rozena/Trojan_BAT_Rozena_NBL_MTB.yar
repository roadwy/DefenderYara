
rule Trojan_BAT_Rozena_NBL_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {06 07 02 07 91 28 10 00 00 0a 03 6f 11 00 00 0a 07 28 10 00 00 0a 03 6f 11 00 00 0a 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 d3 06 2a } //1
		$a_80_1 = {78 6f 72 45 6e 63 44 65 63 } //xorEncDec  1
		$a_80_2 = {61 76 62 79 70 61 73 73 } //avbypass  1
		$a_80_3 = {61 76 62 79 70 61 73 73 2e 70 64 62 } //avbypass.pdb  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}