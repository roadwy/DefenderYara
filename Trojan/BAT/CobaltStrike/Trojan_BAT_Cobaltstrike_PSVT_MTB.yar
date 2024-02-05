
rule Trojan_BAT_Cobaltstrike_PSVT_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PSVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 04 07 08 6f 90 01 01 00 00 0a 16 73 1a 00 00 0a 13 06 00 73 1b 00 00 0a 13 07 00 20 00 04 00 00 8d 0a 00 00 01 13 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}