
rule Trojan_BAT_Downloader_IHU_MTB{
	meta:
		description = "Trojan:BAT/Downloader.IHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 62 31 34 34 37 36 35 34 2d 36 66 38 35 2d 34 37 62 31 2d 38 66 35 37 2d 66 65 61 64 30 65 39 61 34 63 35 32 } //01 00 
		$a_01_1 = {45 6e 74 72 79 } //01 00 
		$a_01_2 = {45 78 65 63 75 74 65 } //01 00 
		$a_01_3 = {46 65 74 63 68 46 69 6c 65 73 } //01 00 
		$a_01_4 = {4d 65 74 68 6f 64 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}