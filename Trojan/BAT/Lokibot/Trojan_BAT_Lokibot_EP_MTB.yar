
rule Trojan_BAT_Lokibot_EP_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 20 ?? ?? ?? ?? 5d 07 11 04 20 ?? ?? ?? ?? 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? ?? 61 07 11 04 17 58 20 ?? ?? ?? ?? 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d b0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}