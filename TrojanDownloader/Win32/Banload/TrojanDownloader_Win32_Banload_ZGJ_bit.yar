
rule TrojanDownloader_Win32_Banload_ZGJ_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZGJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 65 00 73 00 } //02 00  Software\Borland\Delphi\Locales
		$a_01_1 = {0f b6 54 5f fe 0f b7 ce c1 e9 08 66 33 d1 66 89 54 58 fe 0f b6 44 5f fe 66 03 f0 66 69 c6 ff c9 66 05 38 5e 8b f0 43 4d 75 ce } //01 00 
		$a_01_2 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00 6f 00 70 00 65 00 6e 00 } //00 00 
		$a_00_3 = {7e 15 00 00 27 6f ec 40 82 04 1e 5f } //f1 62 
	condition:
		any of ($a_*)
 
}