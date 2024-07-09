
rule Trojan_BAT_CyberGate_ACG_MTB{
	meta:
		description = "Trojan:BAT/CyberGate.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0b 2b 4c 16 13 04 2b 37 03 11 04 07 6f ?? 00 00 0a 0a 08 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 08 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 08 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 17 d6 13 04 11 04 03 6f ?? 00 00 0a 17 da 31 bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}