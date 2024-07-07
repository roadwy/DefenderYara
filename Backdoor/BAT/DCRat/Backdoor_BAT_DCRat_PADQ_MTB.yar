
rule Backdoor_BAT_DCRat_PADQ_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.PADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 06 61 13 0e 16 13 0f 38 2d 00 00 00 11 0f 16 3e 0c 00 00 00 11 0b 1e 62 13 0b 11 0c 1e 58 13 0c 08 11 0a 11 0f 58 11 0e 11 0b 5f 11 0c 1f 1f 5f 64 d2 9c 11 0f 17 58 13 0f 11 0f 06 3f cb } //1
		$a_01_1 = {fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 20 11 00 00 00 64 61 fe 0e 15 00 fe 0c 15 00 fe 0c 11 00 58 fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 20 0f 00 00 00 62 61 fe 0e 15 00 fe 0c 15 00 fe 0c 12 00 58 fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 20 17 00 00 00 64 61 fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 58 fe 0e 15 00 fe 0c 12 00 20 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}