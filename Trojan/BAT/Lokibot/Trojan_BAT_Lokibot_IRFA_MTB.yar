
rule Trojan_BAT_Lokibot_IRFA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.IRFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 04 73 3c 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 01 00 00 1b 0a 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 3b 00 00 01 6f ?? ?? ?? 0a 1a 9a 80 04 00 00 04 23 d1 37 b7 3b 43 62 20 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}