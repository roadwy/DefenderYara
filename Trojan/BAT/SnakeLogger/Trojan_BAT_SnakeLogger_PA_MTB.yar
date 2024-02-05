
rule Trojan_BAT_SnakeLogger_PA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 } //01 00 
		$a_01_1 = {53 2d 2d 2d 2d 2d 2d 2d 2d 4e 2d 2d 2d 2d 2d 2d 2d 2d 41 2d 2d 2d 2d 2d 2d 2d 2d 4b 2d 2d 2d 2d 2d 2d 2d 2d 45 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 4d 49 53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52 4d 49 } //00 00 
	condition:
		any of ($a_*)
 
}