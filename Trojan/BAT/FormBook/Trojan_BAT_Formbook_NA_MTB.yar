
rule Trojan_BAT_Formbook_NA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {93 61 1f 50 5f 9d 30 04 16 0c 2b b4 09 20 26 90 01 03 93 20 cb 90 01 03 59 2b ee 03 2b 01 02 0a 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}