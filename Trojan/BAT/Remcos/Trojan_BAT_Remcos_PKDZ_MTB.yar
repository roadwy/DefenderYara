
rule Trojan_BAT_Remcos_PKDZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PKDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 61 00 00 70 28 24 00 00 0a 0a 72 93 00 00 70 28 24 00 00 0a 0b 28 09 00 00 06 0c 12 02 28 18 00 00 0a 75 03 00 00 1b 0d 12 02 28 19 00 00 0a 73 25 00 00 0a 13 04 11 04 06 07 6f 26 00 00 0a 13 05 73 17 00 00 0a 13 06 11 06 11 05 17 73 27 00 00 0a 13 07 11 07 09 16 09 8e 69 6f 28 00 00 0a 11 06 6f 29 00 00 0a 28 1b 00 00 0a 13 08 dd 2d 00 00 00 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}