
rule Trojan_BAT_Heracles_HNA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 70 17 8d 03 00 00 01 13 ?? 11 ?? 16 ?? 6f ?? 00 00 0a a2 11 ?? 14 14 14 17 28 ?? ?? 00 0a 26 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 8e b7 32 c7 ?? 14 72 ?? ?? 00 70 17 8d 03 00 00 01 13 ?? 11 ?? 16 72 ?? ?? 00 70 a2 11 ?? 14 14 14 28 90 09 13 00 0a 13 ?? 16 13 ?? 2b 31 11 ?? 11 ?? 9a ?? ?? 14 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}