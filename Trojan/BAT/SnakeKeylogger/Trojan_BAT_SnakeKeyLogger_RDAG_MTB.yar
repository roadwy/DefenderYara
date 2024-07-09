
rule Trojan_BAT_SnakeKeyLogger_RDAG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 02 7b ?? ?? ?? ?? 6f 26 00 00 0a 02 7b ?? ?? ?? ?? 6f 27 00 00 0a 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}