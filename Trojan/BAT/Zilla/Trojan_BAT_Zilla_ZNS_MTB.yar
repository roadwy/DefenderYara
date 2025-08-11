
rule Trojan_BAT_Zilla_ZNS_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 7d 12 01 00 04 19 8d ?? 00 00 01 25 16 11 4c 7c ?? 01 00 04 28 ?? 01 00 0a 9c 25 17 11 4c 7c ?? 01 00 04 28 ?? 01 00 0a 9c 25 18 11 4c 7c ?? 01 00 04 28 ?? 01 00 0a 9c 13 50 11 50 7e ?? 01 00 04 25 2d 17 26 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}