
rule Trojan_BAT_Androm_SPFM_MTB{
	meta:
		description = "Trojan:BAT/Androm.SPFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 01 01 07 11 90 01 01 91 13 90 01 01 02 07 11 90 01 01 91 11 90 01 01 61 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}