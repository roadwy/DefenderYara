
rule Trojan_BAT_Remcos_SWA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 08 16 08 8e 69 6f ?? 00 00 0a 17 0b 11 06 6f ?? 00 00 0a 13 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}