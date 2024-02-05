
rule Trojan_BAT_Vidar_MA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 02 16 02 8e 69 6f 90 01 03 0a 00 07 6f 29 00 00 0a 00 06 6f 90 01 03 0a 0c de 16 07 2c 07 07 6f 25 00 00 0a 00 dc 06 2c 07 06 6f 25 00 00 0a 00 dc 08 2a 90 00 } //02 00 
		$a_03_1 = {9c 25 17 1f 58 9c 13 08 11 05 1f 7b 28 90 01 03 0a 13 09 02 08 11 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}