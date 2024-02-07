
rule TrojanDownloader_Win32_Lecpetex_B{
	meta:
		description = "TrojanDownloader:Win32/Lecpetex.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 ec 81 7d ec 90 22 9f 53 72 08 6a 00 ff 15 } //01 00 
		$a_01_1 = {2f 69 6d 61 67 65 73 2f 73 74 6f 72 69 65 73 2f 66 6f 6f 74 62 61 6c 6c 66 69 65 6c 64 2e 6a 70 67 } //01 00  /images/stories/footballfield.jpg
		$a_01_2 = {31 37 36 2e 39 2e 31 31 2e 32 31 36 } //00 00  176.9.11.216
	condition:
		any of ($a_*)
 
}