
rule Trojan_BAT_SnakeKeylogger_SZZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SZZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 20 00 f6 01 00 0d 20 ef be ad de 13 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}