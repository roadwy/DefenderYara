
rule Trojan_O97M_QakbotDocDrops_A{
	meta:
		description = "Trojan:O97M/QakbotDocDrops.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a } //00 00 
	condition:
		any of ($a_*)
 
}