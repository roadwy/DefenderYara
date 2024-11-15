
rule Trojan_BAT_Heracles_KAZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 16 08 06 1a 28 ?? 00 00 0a 06 1a 58 0a 11 04 17 58 13 04 11 04 07 32 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}