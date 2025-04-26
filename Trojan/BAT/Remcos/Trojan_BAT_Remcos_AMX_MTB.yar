
rule Trojan_BAT_Remcos_AMX_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 04 6f ?? 00 00 0a 00 06 05 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 2b 00 08 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}