
rule Trojan_BAT_Androm_AAIV_MTB{
	meta:
		description = "Trojan:BAT/Androm.AAIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 00 00 04 25 3a ?? 00 00 00 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 7e ?? 00 00 04 25 3a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}