
rule Trojan_BAT_MassLogger_BR_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 08 6f ?? 00 00 0a 13 09 04 03 6f ?? 00 00 0a 59 13 0a 11 0a 19 fe 04 16 fe 01 13 0d 11 0d 2c 6a 00 16 13 0e 2b 00 03 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}