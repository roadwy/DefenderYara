
rule Trojan_BAT_MassLogger_CE_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 17 94 2f 09 03 6f ?? 00 00 0a 04 32 b1 07 07 61 0b 09 17 58 0d 09 08 16 94 2f 09 03 6f ?? 00 00 0a 04 } //4
		$a_03_1 = {04 16 31 0c 02 03 7b ?? 00 00 04 6f ?? 00 00 0a 04 17 31 0c 02 03 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}