
rule Trojan_BAT_Remcos_BAC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 0a 11 05 11 0a 11 05 8e 69 5d 91 1f 5a 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d d9 16 13 0c 2b 1e 11 07 11 0c 11 05 11 0c 1d 58 11 05 8e 69 5d 91 20 a7 00 00 00 61 d2 9c 11 0c 17 58 13 0c 11 0c 11 07 8e 69 fe 04 13 0d 11 0d 2d d4 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}