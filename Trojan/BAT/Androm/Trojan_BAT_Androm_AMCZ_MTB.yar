
rule Trojan_BAT_Androm_AMCZ_MTB{
	meta:
		description = "Trojan:BAT/Androm.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 6f ?? 00 00 0a 09 18 6f ?? 00 00 0a 09 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 13 04 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}