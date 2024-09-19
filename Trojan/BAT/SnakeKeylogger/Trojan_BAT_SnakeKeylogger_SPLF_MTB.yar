
rule Trojan_BAT_SnakeKeylogger_SPLF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 16 fe 01 13 05 11 05 2c 0c 02 11 04 02 11 04 91 1f 1d 61 b4 9c 11 04 17 d6 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}