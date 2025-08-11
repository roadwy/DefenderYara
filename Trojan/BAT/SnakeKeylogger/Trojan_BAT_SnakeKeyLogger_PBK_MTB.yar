
rule Trojan_BAT_SnakeKeyLogger_PBK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 07 1f 11 5a 11 07 18 62 61 ?? ?? ?? ?? ?? 60 9e 11 07 17 58 13 07 11 07 06 ?? ?? ?? ?? ?? 8e 69 fe 04 13 08 11 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}