
rule Trojan_BAT_SnakeKeylogger_ABSI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 00 5a 00 2e 00 47 00 65 00 6e 00 65 00 74 00 69 00 63 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //02 00 
		$a_01_1 = {74 00 72 00 61 00 65 00 6b 00 74 00 6f 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}