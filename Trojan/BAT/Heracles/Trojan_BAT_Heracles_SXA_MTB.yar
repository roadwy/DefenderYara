
rule Trojan_BAT_Heracles_SXA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0c 14 0d 07 6f ?? 00 00 0a 8e 2c 10 17 8d ?? 00 00 01 25 16 17 8d ?? 00 00 01 a2 0d 07 08 28 ?? 00 00 0a 09 6f ?? 00 00 0a 26 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}