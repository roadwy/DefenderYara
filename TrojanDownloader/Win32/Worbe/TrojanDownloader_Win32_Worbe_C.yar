
rule TrojanDownloader_Win32_Worbe_C{
	meta:
		description = "TrojanDownloader:Win32/Worbe.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 71 6a 36 6a 36 6a 23 6a 69 6a 6d 6a 6d } //02 00  jqj6j6j#jijmjm
		$a_01_1 = {53 8a 5c 24 0c 56 8b f0 8d 54 24 14 8b 4a 04 83 c2 04 85 c9 7c 05 32 cb 88 0e 46 4f 85 ff 89 7c 24 14 7f e8 } //01 00 
		$a_01_2 = {62 69 6e 32 68 65 78 6e 65 77 2e 70 68 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}