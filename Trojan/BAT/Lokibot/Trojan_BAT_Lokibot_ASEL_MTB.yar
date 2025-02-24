
rule Trojan_BAT_Lokibot_ASEL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ASEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 09 6f ?? 01 00 0a 13 0b 12 0b 28 ?? 01 00 0a 20 ff 00 00 00 fe 01 16 fe 01 13 0c 11 0c 39 ?? 00 00 00 00 09 11 04 12 0b 28 ?? 01 00 0a 9c } //4
		$a_01_1 = {11 04 17 58 13 04 00 11 0a 17 58 13 0a 11 0a 06 fe 04 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}