
rule Trojan_BAT_RedLineStealer_PPBH_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.PPBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 38 ?? 00 00 00 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}