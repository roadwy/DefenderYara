
rule Trojan_BAT_SnakeKeylogger_SPXF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 0d 07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}