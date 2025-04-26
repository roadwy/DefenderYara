
rule Trojan_BAT_SnakeKeylogger_SPVG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 09 17 58 08 5d 91 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 13 06 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}