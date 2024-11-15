
rule Trojan_BAT_Lokibot_AMC_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 18 fe 04 16 fe 01 13 06 11 06 2c 0e 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 19 fe 01 13 07 11 07 2c 0e 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}