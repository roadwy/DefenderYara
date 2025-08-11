
rule Trojan_BAT_MassLogger_AEVA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AEVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 91 16 fe 01 13 07 11 07 2c 0c 08 11 06 20 ff 00 00 00 9c 00 2b 14 00 08 11 06 8f ?? 00 00 01 25 13 08 11 08 47 17 da b4 52 00 11 06 17 d6 13 06 11 06 11 05 31 c7 } //5
		$a_01_1 = {08 11 04 07 07 8e 69 17 da 11 04 da 91 9c 11 04 17 d6 13 04 11 04 09 31 e7 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}