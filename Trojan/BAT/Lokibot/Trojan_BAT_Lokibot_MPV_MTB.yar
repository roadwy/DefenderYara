
rule Trojan_BAT_Lokibot_MPV_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 05 02 20 00 03 00 00 20 32 03 00 00 28 ?? 00 00 2b 58 02 20 95 03 00 00 20 a7 03 00 00 28 ?? 00 00 2b 5d 06 02 20 30 01 00 00 20 03 01 00 00 28 ?? 00 00 2b 58 02 20 03 02 00 00 20 30 02 00 00 28 ?? 00 00 2b 5d 20 02 02 00 00 20 3a 02 00 00 28 a9 00 00 2b 04 03 6f ad 01 00 0a 59 0c 08 03 07 74 4a 00 00 1b 28 01 02 00 06 11 07 20 05 01 00 00 93 20 7a 25 00 00 59 13 05 38 c9 fe ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}