
rule Trojan_BAT_SnakeKeyLogger_RDAP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 0a 11 10 11 08 5d d2 } //00 00 
	condition:
		any of ($a_*)
 
}