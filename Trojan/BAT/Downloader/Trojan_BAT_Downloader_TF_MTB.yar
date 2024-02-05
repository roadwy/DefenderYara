
rule Trojan_BAT_Downloader_TF_MTB{
	meta:
		description = "Trojan:BAT/Downloader.TF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_81_1 = {41 61 72 6f 6e 20 41 63 63 6f 75 6e 74 } //01 00 
		$a_81_2 = {44 61 74 65 54 69 6d 65 40 65 78 61 6d 70 6c 65 2e 63 6f 6d } //01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_4 = {49 6e 76 6f 6b 65 } //01 00 
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_6 = {4b 6b 69 75 70 73 76 77 70 77 77 6e 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}