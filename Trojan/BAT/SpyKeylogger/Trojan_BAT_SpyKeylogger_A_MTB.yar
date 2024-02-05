
rule Trojan_BAT_SpyKeylogger_A_MTB{
	meta:
		description = "Trojan:BAT/SpyKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 06 72 dd 00 00 70 6f 1d 00 00 0a 26 08 16 08 6f 1a 00 00 0a 6f 1b 00 00 0a 26 08 07 6f 1d 00 00 0a 26 11 06 11 05 08 28 03 00 00 06 07 } //00 00 
	condition:
		any of ($a_*)
 
}