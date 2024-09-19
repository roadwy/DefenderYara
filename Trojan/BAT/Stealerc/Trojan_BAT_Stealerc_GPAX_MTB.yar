
rule Trojan_BAT_Stealerc_GPAX_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 06 11 ?? 6f ?? 00 00 0a 13 ?? 08 07 6a 5a 11 ?? 6a 58 0c 00 11 ?? 17 58 13 ?? 11 ?? 09 fe 04 13 ?? 11 ?? 2d d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}