
rule TrojanDownloader_Win32_Unruy_E{
	meta:
		description = "TrojanDownloader:Win32/Unruy.E,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 45 20 57 45 20 47 4f } //01 00  RE WE GO
		$a_00_1 = {31 32 32 2e 31 34 31 2e 38 36 2e 31 32 } //01 00  122.141.86.12
		$a_02_2 = {25 73 69 65 78 70 6c 6f 72 65 2e 65 78 65 90 02 04 52 55 4e 41 53 90 02 04 2e 62 61 74 90 00 } //0a 00 
		$a_02_3 = {8b 45 fc 8b 00 8b 4d fc 8b 49 04 03 48 28 89 4d f4 a1 90 01 04 83 c0 07 a3 90 01 04 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 01 04 6b c9 05 2b c1 a3 90 01 04 6a 00 6a 00 8b 45 fc ff 70 04 ff 55 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}