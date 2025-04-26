
rule Trojan_BAT_SnakeLogger_SXO_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}