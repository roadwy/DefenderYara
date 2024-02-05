
rule Trojan_BAT_SnakeKeylogger_D_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {5d 91 61 28 } //02 00 
		$a_03_1 = {8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}