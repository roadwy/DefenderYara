
rule Trojan_BAT_PrivateLoader_A_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 14 20 ?? 00 00 00 28 ?? 00 00 06 20 ?? 01 00 00 28 ?? 00 00 06 72 01 00 00 70 28 ?? 00 00 06 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}