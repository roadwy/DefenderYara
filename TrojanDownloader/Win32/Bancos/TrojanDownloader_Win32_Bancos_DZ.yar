
rule TrojanDownloader_Win32_Bancos_DZ{
	meta:
		description = "TrojanDownloader:Win32/Bancos.DZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {63 6d 64 20 2f 6b 20 63 3a 5c 90 02 08 2e 67 69 66 90 00 } //01 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 68 6f 6e 2d 73 61 6d 73 6f 6e 2e 62 65 2f 6a 73 2f 5f 6e 6f 74 65 73 2f 90 02 08 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}