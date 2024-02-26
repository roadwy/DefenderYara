
rule Trojan_BAT_SnakeKeylogger_SPDX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 38 72 ff ff ff 0b 38 72 ff ff ff 06 38 73 ff ff ff 28 90 01 03 2b 38 6e ff ff ff 28 90 01 03 2b 38 69 ff ff ff 28 90 01 03 0a 38 64 ff ff ff 02 38 63 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}