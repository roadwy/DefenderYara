
rule Trojan_BAT_Lokibot_XDAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.XDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 05 0e 04 6f ?? 00 00 0a 0a 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 0b } //3
		$a_03_1 = {02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 16 0b 2b c6 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}