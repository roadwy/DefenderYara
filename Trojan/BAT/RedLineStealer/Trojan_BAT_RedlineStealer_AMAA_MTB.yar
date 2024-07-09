
rule Trojan_BAT_RedlineStealer_AMAA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 09 08 91 09 07 91 58 20 00 01 00 00 5d 13 ?? 03 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 09 11 ?? 91 61 d2 81 ?? 00 00 01 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}