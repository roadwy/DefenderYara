
rule Trojan_BAT_Heracles_MBWQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f ?? 00 00 0a 02 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 0b 72 01 00 00 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}