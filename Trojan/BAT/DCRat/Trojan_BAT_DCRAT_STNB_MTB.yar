
rule Trojan_BAT_DCRAT_STNB_MTB{
	meta:
		description = "Trojan:BAT/DCRAT.STNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 00 08 20 00 04 00 00 58 28 90 01 03 2b 00 07 02 08 20 00 04 00 00 6f 90 01 03 0a 0d 08 09 58 0c 09 20 00 04 00 00 fe 04 16 fe 01 13 05 11 05 2d 0c 00 0f 00 08 28 90 01 03 2b 00 2b 06 00 17 13 05 2b bb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}