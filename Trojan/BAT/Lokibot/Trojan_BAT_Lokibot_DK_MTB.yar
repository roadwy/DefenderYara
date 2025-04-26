
rule Trojan_BAT_Lokibot_DK_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 09 11 05 9e 11 07 11 07 07 94 11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 08 17 58 0c 08 02 8e 69 32 a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}