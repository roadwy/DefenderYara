
rule TrojanDownloader_Win32_Popagerty_A{
	meta:
		description = "TrojanDownloader:Win32/Popagerty.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 67 6f 70 6f 70 5c 67 6f 67 6f 70 6f 70 2e 65 78 65 00 } //01 00 
		$a_01_1 = {70 6f 70 75 70 67 75 69 64 65 5f 53 65 74 75 70 5f 73 69 6c 65 6e 74 5f 00 } //01 00 
		$a_01_2 = {64 6f 77 6e 2e 70 6f 70 2d 75 70 67 75 69 64 65 2e 63 6f 6d 2f 73 65 74 75 70 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}