
rule Trojan_BAT_SnakeKeyLogger_TL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 91 06 ?? ?? ?? ?? ?? 11 05 91 13 08 07 61 11 08 61 13 09 11 0c 1f ?? 91 11 0c 20 ?? ?? ?? ?? 91 59 13 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}