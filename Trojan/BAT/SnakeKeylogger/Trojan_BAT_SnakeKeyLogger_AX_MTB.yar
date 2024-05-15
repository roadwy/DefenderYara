
rule Trojan_BAT_SnakeKeyLogger_AX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 0f 11 0e 11 0f 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07 } //00 00 
	condition:
		any of ($a_*)
 
}