
rule Trojan_BAT_Nanocore_PTEI_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.PTEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 03 00 00 06 0d 09 28 90 01 01 00 00 0a 13 04 11 04 28 90 01 01 00 00 0a 13 05 07 11 05 6f 4b 00 00 0a 00 07 13 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}