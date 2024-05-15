
rule Trojan_BAT_SnakeKeylogger_SPVX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {59 20 00 01 00 00 58 20 00 01 00 00 5d 13 90 01 01 07 11 90 01 01 11 90 01 01 6a 5d d4 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}