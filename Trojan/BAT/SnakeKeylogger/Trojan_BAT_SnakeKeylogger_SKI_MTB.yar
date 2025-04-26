
rule Trojan_BAT_SnakeKeylogger_SKI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 06 13 07 11 07 16 30 02 2b 33 03 19 8d 44 00 00 01 25 16 12 02 28 53 00 00 0a 9c 25 17 12 02 28 54 00 00 0a 9c 25 18 12 02 28 55 00 00 0a 9c 09 28 01 00 00 2b 6f 56 00 00 0a 00 2b 00 00 } //1
		$a_81_1 = {24 38 37 62 63 37 63 35 34 2d 63 37 37 39 2d 34 33 63 33 2d 62 34 36 34 2d 61 65 63 61 38 36 34 35 33 30 62 38 } //1 $87bc7c54-c779-43c3-b464-aeca864530b8
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}