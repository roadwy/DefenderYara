
rule Trojan_BAT_SnakeKeylogger_SYRA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SYRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 11 11 1d 11 09 91 13 27 11 1d 11 09 11 27 11 22 61 19 11 1a 58 61 11 2f 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}