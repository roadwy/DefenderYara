
rule Trojan_BAT_SnakeKeylogger_SPAI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 07 16 73 ?? ?? ?? 0a 13 04 11 04 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 05 de 2a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}