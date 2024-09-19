
rule Trojan_BAT_SnakeKeylogger_SJVP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SJVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 13 0e 11 18 11 09 91 13 20 11 18 11 09 11 20 11 28 61 19 11 1c 58 61 11 30 61 d2 9c 17 11 09 58 13 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}