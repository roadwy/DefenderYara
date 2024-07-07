
rule Trojan_BAT_Kryptik_XL_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.XL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 6f 90 02 04 0d 06 09 28 90 02 04 08 da 28 90 02 04 28 90 02 04 28 90 02 04 0a 11 04 17 d6 13 04 00 11 04 11 06 fe 04 13 07 11 07 2d ca 90 00 } //10
		$a_80_1 = {45 6e 74 72 79 50 6f 69 6e 74 } //EntryPoint  2
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  2
		$a_80_3 = {49 6e 76 6f 6b 65 } //Invoke  2
		$a_80_4 = {41 73 73 65 6d 62 6c 79 } //Assembly  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}