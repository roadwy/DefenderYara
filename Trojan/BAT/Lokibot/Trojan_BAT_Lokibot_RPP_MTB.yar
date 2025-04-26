
rule Trojan_BAT_Lokibot_RPP_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 59 20 00 01 00 00 6a 58 20 00 01 00 00 6a 5d d2 9c 00 07 15 58 0b 07 6c 23 00 00 00 00 00 00 00 00 23 00 00 00 00 00 00 00 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}