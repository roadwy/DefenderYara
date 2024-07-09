
rule Trojan_BAT_Lokibot_MOYF_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MOYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 0c 16 13 04 2b 21 00 07 11 04 08 11 04 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 07 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}