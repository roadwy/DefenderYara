
rule Trojan_BAT_SnakeKeylogger_SJQA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SJQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 13 11 11 1d 11 09 91 13 27 11 1d 11 09 11 22 11 27 61 11 1a 19 58 61 11 2f 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}