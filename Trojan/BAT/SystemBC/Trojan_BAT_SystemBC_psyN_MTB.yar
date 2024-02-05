
rule Trojan_BAT_SystemBC_psyN_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.psyN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {02 28 1c 00 00 0a 02 1f 2a 7d 02 00 00 04 02 72 0d 00 00 70 7d 03 00 00 04 2a } //00 00 
	condition:
		any of ($a_*)
 
}