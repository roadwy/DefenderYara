
rule Backdoor_BAT_Androm_KAAF_MTB{
	meta:
		description = "Backdoor:BAT/Androm.KAAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 07 11 07 11 01 94 11 07 11 03 94 58 20 00 90 01 01 00 00 5d 94 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}