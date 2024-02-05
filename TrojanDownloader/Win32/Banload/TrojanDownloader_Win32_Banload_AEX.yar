
rule TrojanDownloader_Win32_Banload_AEX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AEX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 b8 0b 00 00 e8 90 01 04 a1 90 01 03 00 8b 00 e8 90 01 04 c3 90 02 07 3a 5c 57 69 6e 64 6f 77 73 5c 90 02 10 2e 65 78 65 00 90 02 05 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}