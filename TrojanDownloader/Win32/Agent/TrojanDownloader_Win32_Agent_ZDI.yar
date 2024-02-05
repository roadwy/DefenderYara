
rule TrojanDownloader_Win32_Agent_ZDI{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 0c 00 00 00 68 90 01 04 8b 4d 08 8b 51 38 52 e8 90 01 04 89 90 01 02 ff ff ff c7 90 01 02 ff ff ff 08 00 00 00 8d 90 01 02 ff ff ff 8d 90 01 02 ff 15 90 00 } //01 00 
		$a_00_1 = {77 00 79 00 66 00 5b 00 31 00 5d 00 2e 00 63 00 73 00 73 00 } //01 00 
		$a_00_2 = {64 00 6f 00 77 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}