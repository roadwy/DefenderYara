
rule Trojan_BAT_Formbook_MBFM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 1b 03 04 61 05 59 20 00 01 00 00 58 0a 07 } //01 00 
		$a_01_1 = {4d 56 65 00 63 75 72 72 65 6e 74 56 61 6c 75 65 00 70 73 56 61 6c 75 } //00 00 
	condition:
		any of ($a_*)
 
}