
rule Trojan_BAT_RedLineStealer_KAE_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 1c 8f ?? 00 00 01 25 4a 11 05 11 1c 11 1d 28 31 00 00 0a 58 54 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}