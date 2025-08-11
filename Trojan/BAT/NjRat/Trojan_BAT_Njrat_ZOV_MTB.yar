
rule Trojan_BAT_Njrat_ZOV_MTB{
	meta:
		description = "Trojan:BAT/Njrat.ZOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 07 11 07 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06 11 06 02 16 6f ?? 00 00 0a 32 8f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}