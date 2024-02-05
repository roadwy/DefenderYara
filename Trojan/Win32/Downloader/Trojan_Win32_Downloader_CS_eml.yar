
rule Trojan_Win32_Downloader_CS_eml{
	meta:
		description = "Trojan:Win32/Downloader.CS!eml,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {30 30 31 2e 65 78 65 90 0a 18 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 90 00 } //01 00 
		$a_01_1 = {5c 77 63 2e 64 61 74 } //02 00 
		$a_01_2 = {5c 66 78 67 61 6d 65 2e 65 78 65 } //01 00 
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //02 00 
		$a_03_4 = {31 31 30 33 2f 90 0a 20 00 68 74 74 70 3a 2f 2f 90 02 0f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}