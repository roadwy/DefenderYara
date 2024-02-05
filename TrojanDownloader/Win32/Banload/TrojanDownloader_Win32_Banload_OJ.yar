
rule TrojanDownloader_Win32_Banload_OJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.OJ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 6d 6b 69 6c 2e 65 78 65 90 02 10 68 74 74 70 3a 2f 2f 90 02 25 6d 73 6e 2e 70 6e 67 90 00 } //02 00 
		$a_03_1 = {73 69 73 2e 65 78 65 90 02 10 68 74 74 70 3a 2f 2f 90 02 25 2e 70 6e 67 90 00 } //02 00 
		$a_03_2 = {73 6d 6d 2e 65 78 65 90 02 10 68 74 74 70 3a 2f 2f 90 02 25 2e 70 6e 67 90 00 } //02 00 
		$a_03_3 = {73 69 73 73 2e 65 78 65 90 02 10 68 74 74 70 3a 2f 2f 90 02 25 2e 70 6e 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}