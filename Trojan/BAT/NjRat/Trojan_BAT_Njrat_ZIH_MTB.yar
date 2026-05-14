
rule Trojan_BAT_Njrat_ZIH_MTB{
	meta:
		description = "Trojan:BAT/Njrat.ZIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1f 09 13 0e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}