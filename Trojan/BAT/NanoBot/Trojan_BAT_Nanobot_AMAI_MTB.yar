
rule Trojan_BAT_Nanobot_AMAI_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 11 04 11 05 91 20 ?? ?? ?? ?? 59 d2 9c 00 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 06 11 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}