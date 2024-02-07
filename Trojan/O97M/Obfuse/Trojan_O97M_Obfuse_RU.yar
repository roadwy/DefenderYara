
rule Trojan_O97M_Obfuse_RU{
	meta:
		description = "Trojan:O97M/Obfuse.RU,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //01 00  Private Sub Document_open()
		$a_03_1 = {5b 49 6e 74 65 72 61 63 74 69 6f 6e 5d 2e 53 68 65 6c 6c 28 90 02 10 2c 20 90 02 10 29 2c 20 90 02 10 29 90 00 } //01 00 
		$a_01_2 = {2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 } //01 00  .TextRange.Text
		$a_03_3 = {53 68 61 70 65 73 28 22 90 02 20 22 29 2e 54 65 78 74 46 72 61 6d 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}