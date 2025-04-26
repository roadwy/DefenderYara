
rule Trojan_BAT_SnakeKeylogger_KAG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 5a 58 20 00 01 00 00 5e 13 05 04 08 03 08 91 05 09 95 61 d2 9c 1e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}