
rule Trojan_BAT_AveMaria_RE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {0d 06 08 94 13 04 06 08 06 09 94 9e 06 09 11 04 9e 00 08 17 59 0c 08 16 fe 02 13 05 11 05 2d d6 06 13 06 2b 00 11 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}