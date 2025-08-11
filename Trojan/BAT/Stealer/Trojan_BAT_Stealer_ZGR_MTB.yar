
rule Trojan_BAT_Stealer_ZGR_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ZGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? 13 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 0e 05 39 ?? 00 00 00 23 89 41 60 e5 d0 22 d3 3f 07 7b ?? 00 00 04 6c 5a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}