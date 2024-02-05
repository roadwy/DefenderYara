
rule Trojan_VBA_Downldr_ARO_eml{
	meta:
		description = "Trojan:VBA/Downldr.ARO!eml,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 90 02 01 28 90 02 2f 29 90 00 } //05 00 
		$a_03_1 = {20 2b 20 49 49 66 28 28 90 02 03 20 2b 20 90 02 03 29 20 3d 20 90 02 03 2c 20 22 90 02 05 22 2c 20 22 90 02 0a 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}