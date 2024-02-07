
rule Trojan_AndroidOS_Xenomorph_B{
	meta:
		description = "Trojan:AndroidOS/Xenomorph.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 65 77 45 62 4a } //01 00  uewEbJ
		$a_01_1 = {43 6f 6f 6b 69 65 47 72 61 62 62 65 72 41 63 74 69 76 69 74 79 } //01 00  CookieGrabberActivity
		$a_01_2 = {4c 6d 65 72 69 74 6f 72 69 6f 75 73 6e 65 73 73 2f 6d 6f 6c 6c 61 68 2f 70 72 65 73 73 65 72 2f } //00 00  Lmeritoriousness/mollah/presser/
	condition:
		any of ($a_*)
 
}