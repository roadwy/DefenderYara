
rule Trojan_BAT_Formbook_RDAH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 75 09 00 00 1b 1f 18 9a 6f 41 00 00 0a 0c 08 74 0a 00 00 1b 28 03 00 00 2b 0d 1a 13 09 } //00 00 
	condition:
		any of ($a_*)
 
}