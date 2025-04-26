
rule Trojan_BAT_Lokibot_MBEM_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MBEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 07 6f ?? 01 00 0a 13 13 16 0d 11 05 06 9a ?? ?? ?? ?? ?? 28 ?? 01 00 06 28 ?? 00 00 0a 13 0c 11 0c 2c 0a 12 13 28 ?? 01 00 0a 0d 2b 44 11 05 06 9a ?? ?? ?? ?? ?? 28 ?? 01 00 06 28 ?? 00 00 0a 13 0d 11 0d 2c 0a 12 13 28 ?? 01 00 0a 0d 2b 21 11 05 06 9a ?? ?? ?? ?? ?? 28 a4 01 00 06 28 ?? 00 00 0a 13 0e 11 0e 2c 08 12 13 28 ?? 01 00 0a 0d 11 06 09 6f ?? 01 00 0a 08 17 58 0c 08 11 08 fe 04 13 0f 11 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}