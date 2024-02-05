
rule Trojan_BAT_Vidar_AF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {fa 25 33 00 16 90 01 02 01 90 01 03 19 90 01 03 02 90 01 03 02 90 01 03 01 90 01 03 17 90 01 03 0a 90 01 03 01 90 01 03 02 90 01 03 01 90 00 } //03 00 
		$a_80_1 = {77 65 62 43 6c 69 65 6e 74 } //webClient  03 00 
		$a_80_2 = {45 6e 61 62 6c 65 56 69 73 75 61 6c 53 74 79 6c 65 73 } //EnableVisualStyles  03 00 
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  03 00 
		$a_80_4 = {64 69 73 63 6f 72 64 } //discord  00 00 
	condition:
		any of ($a_*)
 
}