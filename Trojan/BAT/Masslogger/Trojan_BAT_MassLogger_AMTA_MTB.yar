
rule Trojan_BAT_MassLogger_AMTA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AMTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 1a 2f 07 16 0b dd 8d 00 00 00 06 73 ?? 00 00 0a 0c 16 2d 44 2b 47 2b 48 2b 49 2b 4e 2b 4f 8d ?? 00 00 01 2b 4b 2b 4d 16 2b 4d 2b 52 16 09 11 05 02 11 04 28 ?? 00 00 06 de 0f 11 05 2c 0a 16 2d 07 11 05 6f ?? 00 00 0a dc 03 72 ?? 00 00 70 11 04 28 ?? 00 00 06 17 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}