
rule Trojan_BAT_MassLogger_AFOA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AFOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 8f 01 00 00 01 25 71 01 00 00 01 11 07 0e 04 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 01 00 00 01 1d 13 10 38 ?? fe ff ff 11 07 17 59 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}