
rule Trojan_BAT_Injuke_OQAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.OQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 09 02 11 09 91 66 d2 9c 02 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 72 59 d2 81 ?? 00 00 01 02 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 33 58 d2 81 ?? 00 00 01 00 11 09 17 58 13 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}