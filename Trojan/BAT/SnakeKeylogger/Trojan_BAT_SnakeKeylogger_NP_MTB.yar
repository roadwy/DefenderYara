
rule Trojan_BAT_SnakeKeylogger_NP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d7 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 6d 00 00 00 19 00 00 00 56 00 00 00 4a 01 00 00 34 00 00 00 01 00 00 00 bf 00 00 00 1f 00 00 00 01 } //01 00 
		$a_81_1 = {53 41 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 53 } //00 00 
	condition:
		any of ($a_*)
 
}