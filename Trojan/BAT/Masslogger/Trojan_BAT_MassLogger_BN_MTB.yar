
rule Trojan_BAT_MassLogger_BN_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0f 00 28 ?? 00 00 0a 58 0f 00 28 ?? 00 00 0a 58 0a 06 19 5a 20 00 01 00 00 5d 0a 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 1f 55 61 d2 9c 25 17 } //4
		$a_03_1 = {a2 0b 02 03 04 6f ?? 00 00 0a 0c 0e 04 05 6f ?? 00 00 0a 59 0d 06 1c fe 04 16 fe 01 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}