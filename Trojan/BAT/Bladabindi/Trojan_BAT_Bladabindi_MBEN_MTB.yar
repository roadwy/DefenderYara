
rule Trojan_BAT_Bladabindi_MBEN_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 1e 8d ?? 00 00 01 0a 09 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 16 06 16 1e 28 ?? 00 00 0a 00 07 06 6f ?? 00 00 0a 00 07 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}