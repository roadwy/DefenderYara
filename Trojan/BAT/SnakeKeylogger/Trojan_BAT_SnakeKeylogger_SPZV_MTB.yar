
rule Trojan_BAT_SnakeKeylogger_SPZV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 1f 16 5d 91 13 0c 08 11 05 11 0b 11 0c 61 08 11 0a 91 11 04 58 11 04 5d 59 d2 9c 06 17 58 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}