
rule TrojanDownloader_Win32_Small_CCC{
	meta:
		description = "TrojanDownloader:Win32/Small.CCC,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {b8 20 20 20 20 0b 90 01 01 81 90 01 01 65 78 70 6c 0f 85 90 01 01 00 00 00 8b 90 01 01 04 0b 90 01 01 81 90 01 01 6f 72 65 72 0f 85 90 01 01 00 00 00 8b 90 01 01 08 0b 90 01 01 81 90 01 01 2e 65 78 65 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_00_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  explorer.exe
		$a_00_2 = {70 73 61 70 69 2e 64 6c 6c } //00 00  psapi.dll
	condition:
		any of ($a_*)
 
}