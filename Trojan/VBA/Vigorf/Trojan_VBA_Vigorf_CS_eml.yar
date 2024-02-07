
rule Trojan_VBA_Vigorf_CS_eml{
	meta:
		description = "Trojan:VBA/Vigorf.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 } //02 00  Sub AutoClose()
		$a_03_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 20 29 2e 52 75 6e 20 90 02 0f 2c 20 30 90 00 } //02 00 
		$a_03_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 0f 22 90 00 } //02 00 
		$a_03_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 90 02 0f 2c 20 76 62 48 69 64 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}