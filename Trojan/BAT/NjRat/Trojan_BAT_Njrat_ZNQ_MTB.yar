
rule Trojan_BAT_Njrat_ZNQ_MTB{
	meta:
		description = "Trojan:BAT/Njrat.ZNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 0c 08 0a 1f 0a 2b 38 2b ae 08 11 05 02 11 05 91 09 61 11 04 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 25 26 17 da fe 01 13 07 11 07 2c 49 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}