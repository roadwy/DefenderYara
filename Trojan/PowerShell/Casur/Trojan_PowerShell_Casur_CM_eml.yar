
rule Trojan_PowerShell_Casur_CM_eml{
	meta:
		description = "Trojan:PowerShell/Casur.CM!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 70 61 63 65 28 31 30 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 90 0a 50 00 46 6f 72 20 45 61 63 68 90 02 0e 20 49 6e 20 90 02 0f 0d 0a 90 02 0f 20 3d 20 90 1b 03 20 26 20 90 00 } //01 00 
		$a_03_1 = {3d 20 53 70 6c 69 74 28 90 02 0f 2c 20 90 02 0e 28 22 90 02 03 22 29 90 00 } //01 00 
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 0e 2c 20 90 02 0f 22 90 02 03 22 2c 20 90 02 0f 22 90 02 03 22 29 90 00 } //01 00 
		$a_00_3 = {44 65 62 75 67 2e 50 72 69 6e 74 } //00 00  Debug.Print
	condition:
		any of ($a_*)
 
}