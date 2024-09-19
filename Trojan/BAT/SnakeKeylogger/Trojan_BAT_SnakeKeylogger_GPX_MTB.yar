
rule Trojan_BAT_SnakeKeylogger_GPX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 91 11 ?? 61 13 ?? 06 17 58 08 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}