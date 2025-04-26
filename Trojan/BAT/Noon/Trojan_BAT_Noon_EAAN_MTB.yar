
rule Trojan_BAT_Noon_EAAN_MTB{
	meta:
		description = "Trojan:BAT/Noon.EAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 11 07 11 07 19 5d 2c 09 11 07 1b 5d 16 fe 01 2b 01 17 9c 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08 2d d7 } //5
		$a_01_1 = {11 0d 11 0e 6f 1c 00 00 0a 13 0f 00 09 11 0f 1f 11 5a 58 0d 09 09 19 62 09 1b 63 60 61 0d 00 11 0e 17 58 13 0e 11 0e 11 0d 6f 1d 00 00 0a 32 d0 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}