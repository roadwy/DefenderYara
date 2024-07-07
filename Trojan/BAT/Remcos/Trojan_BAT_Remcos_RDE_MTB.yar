
rule Trojan_BAT_Remcos_RDE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 74 00 72 00 69 00 78 00 20 00 41 00 72 00 63 00 68 00 69 00 74 00 65 00 63 00 74 00 75 00 72 00 61 00 6c 00 } //1 Matrix Architectural
		$a_01_1 = {44 00 65 00 6d 00 6f 00 67 00 72 00 61 00 70 00 68 00 65 00 72 00 } //1 Demographer
		$a_01_2 = {11 07 11 05 25 17 58 13 05 11 0b 1f 18 64 d2 9c 08 11 0a 8f 37 00 00 01 25 4b 11 0b 61 54 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}