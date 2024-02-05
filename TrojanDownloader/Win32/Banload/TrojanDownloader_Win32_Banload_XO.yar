
rule TrojanDownloader_Win32_Banload_XO{
	meta:
		description = "TrojanDownloader:Win32/Banload.XO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {43 42 78 46 6e 6c 7a } //04 00 
		$a_01_1 = {54 6d 72 56 72 66 63 } //02 00 
		$a_01_2 = {54 00 46 00 52 00 4d 00 55 00 4e 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}