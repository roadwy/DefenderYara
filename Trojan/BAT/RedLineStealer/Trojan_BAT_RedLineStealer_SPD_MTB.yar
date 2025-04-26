
rule Trojan_BAT_RedLineStealer_SPD_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 7e 1c 00 00 04 06 91 20 b0 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 1c 00 00 04 8e 69 fe 04 0b 07 2d d7 } //5
		$a_01_1 = {4d 00 61 00 64 00 65 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 MadeConnectionString
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}