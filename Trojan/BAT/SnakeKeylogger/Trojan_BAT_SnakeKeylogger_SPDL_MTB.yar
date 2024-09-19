
rule Trojan_BAT_SnakeKeylogger_SPDL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e 04 61 0e 05 59 20 00 02 00 00 58 0c 08 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}