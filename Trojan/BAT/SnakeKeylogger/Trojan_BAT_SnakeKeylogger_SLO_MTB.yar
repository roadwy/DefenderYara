
rule Trojan_BAT_SnakeKeylogger_SLO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SLO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 20 00 7e 01 00 0d 07 08 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}