
rule TrojanDownloader_Win32_Agent_ADH{
	meta:
		description = "TrojanDownloader:Win32/Agent.ADH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 78 2f 74 78 74 2e 74 78 74 } //01 00  .x/txt.txt
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 45 6e 64 } //01 00  DownloadEnd
		$a_01_2 = {52 65 67 69 73 74 65 72 65 64 00 00 00 00 5c 6d 73 68 6e 74 66 79 31 36 2e 64 61 74 00 00 5c 6d 73 68 64 } //00 00 
	condition:
		any of ($a_*)
 
}