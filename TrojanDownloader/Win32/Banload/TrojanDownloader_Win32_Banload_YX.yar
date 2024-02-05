
rule TrojanDownloader_Win32_Banload_YX{
	meta:
		description = "TrojanDownloader:Win32/Banload.YX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {54 00 55 00 54 00 46 00 4d 00 5f 00 43 00 41 00 44 00 41 00 53 00 54 00 52 00 4f 00 } //02 00 
		$a_01_1 = {54 6d 5f 53 79 73 74 65 6d 54 69 6d 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}