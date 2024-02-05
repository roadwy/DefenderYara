
rule Trojan_BAT_SnakeKeylogger_NL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 df b6 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a3 00 00 00 3b 00 00 00 fd 00 00 00 cf 03 00 00 87 01 00 00 02 00 00 00 68 01 00 00 05 00 00 00 a2 00 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}