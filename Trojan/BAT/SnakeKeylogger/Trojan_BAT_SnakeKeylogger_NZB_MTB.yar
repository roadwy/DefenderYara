
rule Trojan_BAT_SnakeKeylogger_NZB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 52 30 35 33 36 00 73 65 74 5f 52 30 35 33 36 00 52 30 35 33 35 00 63 63 63 00 52 30 35 33 37 00 42 69 74 6d 61 70 00 52 30 35 33 38 } //01 00 
		$a_81_1 = {52 30 35 33 39 } //00 00 
	condition:
		any of ($a_*)
 
}