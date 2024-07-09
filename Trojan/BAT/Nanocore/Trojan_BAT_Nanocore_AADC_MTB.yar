
rule Trojan_BAT_Nanocore_AADC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 17 8d ?? 00 00 01 25 16 1f 2d 9d 6f ?? 00 00 0a 0c 08 8e 69 8d ?? 00 00 01 0d 16 0a 2b 11 09 06 08 06 9a 1f 10 28 ?? 00 00 0a 9c 06 17 58 0a 06 08 8e 69 fe 04 13 09 11 09 2d e3 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}