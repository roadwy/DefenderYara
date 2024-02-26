
rule Trojan_BAT_SnakeKeyLogger_RDAB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 9e 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}