
rule Trojan_BAT_Remcos_ACSB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ACSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 12 02 fe ?? ?? 00 00 01 6f ?? 00 00 0a 72 01 00 00 70 28 ?? 00 00 0a 28 0c 00 00 0a 0b 00 07 06 28 ?? 00 00 0a 00 73 ?? 00 00 0a 13 06 11 06 72 0b 00 00 70 6f ?? 00 00 0a 00 11 06 72 1b 00 00 70 07 72 25 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 06 17 6f ?? 00 00 0a 00 11 06 17 6f ?? 00 00 0a 00 11 06 16 6f ?? 00 00 0a 00 11 06 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}