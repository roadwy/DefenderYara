
rule Trojan_BAT_SnakeKeylogger_SPDV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 11 0e 20 ?? ?? ?? 00 5d 91 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 59 d2 9c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}