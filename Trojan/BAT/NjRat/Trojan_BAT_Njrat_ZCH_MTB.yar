
rule Trojan_BAT_Njrat_ZCH_MTB{
	meta:
		description = "Trojan:BAT/Njrat.ZCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 5a 40 02 70 02 11 04 18 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 11 05 03 08 6f ?? 00 00 0a 61 13 06 07 11 06 28 ?? 00 00 0a 6f ?? 00 00 0a 26 08 17 d6 0c 08 03 6f ?? 00 00 0a fe 04 16 fe 01 13 07 11 07 2c 02 16 0c 11 04 18 d6 13 04 11 04 09 31 a9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}