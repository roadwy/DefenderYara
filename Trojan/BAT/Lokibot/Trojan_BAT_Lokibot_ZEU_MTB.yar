
rule Trojan_BAT_Lokibot_ZEU_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ZEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 0f 20 86 00 00 00 93 20 f4 a2 00 00 59 13 0e 2b 99 04 20 bb 63 41 7b 61 02 61 0a 7e ?? 00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 11 10 20 b3 00 00 00 94 11 10 20 b3 00 00 00 94 59 13 0e 38 60 ff ff ff 7e ?? 00 00 04 74 ?? 00 00 1b 07 9a 25 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}