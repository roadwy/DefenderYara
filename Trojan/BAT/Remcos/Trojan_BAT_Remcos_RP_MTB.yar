
rule Trojan_BAT_Remcos_RP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 59 08 8e 69 59 13 07 11 07 8d ?? 00 00 01 13 08 07 11 05 08 8e 69 58 11 08 16 11 07 28 ?? 00 00 0a 00 11 08 13 15 2b 00 11 15 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}