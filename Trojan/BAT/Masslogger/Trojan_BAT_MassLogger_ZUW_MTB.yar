
rule Trojan_BAT_MassLogger_ZUW_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 05 6f ?? 00 00 0a 13 08 00 de 0e 26 00 28 ?? 00 00 0a 13 08 dd 45 01 00 00 04 03 6f ?? 00 00 0a 59 13 09 11 04 7e ?? 00 00 0a 28 ?? 00 00 0a 13 0c 11 0c 2c 02 00 00 11 09 06 6f ?? 00 00 0a 17 58 fe 04 16 fe 01 13 0d 11 0d 2c 71 00 12 08 28 ?? 00 00 0a 16 61 d2 13 0e 12 08 28 ?? 00 00 0a 16 61 d2 13 0f 12 08 28 ?? 00 00 0a 16 61 d2 13 10 00 07 16 fe 03 13 11 11 11 2c 1f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}