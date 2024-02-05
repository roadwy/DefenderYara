
rule Trojan_BAT_Zusy_PSUG_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 07 28 1c 00 00 0a 72 91 00 00 70 73 1d 00 00 0a 13 09 11 08 72 b3 00 00 70 11 09 } //00 00 
	condition:
		any of ($a_*)
 
}