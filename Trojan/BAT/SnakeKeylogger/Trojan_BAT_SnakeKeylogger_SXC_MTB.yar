
rule Trojan_BAT_SnakeKeylogger_SXC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {73 09 00 00 0a 72 01 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2c cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}