
rule Trojan_BAT_SnakeKeylogger_SPZZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1f 16 5d 91 61 07 11 07 91 11 05 58 11 05 5d 59 d2 9c 11 04 17 58 13 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}