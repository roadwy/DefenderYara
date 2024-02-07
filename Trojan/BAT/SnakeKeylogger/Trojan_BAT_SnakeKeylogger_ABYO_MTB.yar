
rule Trojan_BAT_SnakeKeylogger_ABYO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 03 16 02 8e 69 6f 90 01 01 00 00 0a 0a 2b 00 06 2a 90 0a 19 00 7e 90 01 01 00 00 04 6f 90 00 } //01 00 
		$a_01_1 = {53 00 70 00 61 00 63 00 65 00 54 00 65 00 61 00 6d 00 } //00 00  SpaceTeam
	condition:
		any of ($a_*)
 
}