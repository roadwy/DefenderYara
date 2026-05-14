
rule Trojan_BAT_Remcos_ZTG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 06 11 04 6f ?? 01 00 0a 13 14 09 07 6f ?? 00 00 0a 59 13 06 11 06 19 fe 04 16 fe 01 2c 50 19 8d ?? 00 00 01 25 16 12 14 28 ?? 01 00 0a 9c 25 17 12 14 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}