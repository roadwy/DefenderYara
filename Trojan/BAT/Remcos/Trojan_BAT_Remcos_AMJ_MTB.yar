
rule Trojan_BAT_Remcos_AMJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 2b 29 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}