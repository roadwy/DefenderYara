
rule TrojanDownloader_Win32_Tiny_GX{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 56 43 48 30 53 54 2e 45 58 45 } //01 00  C:\Program Files\Internet Explorer\SVCH0ST.EXE
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 5c 64 65 66 72 65 6e 6c 74 2e 77 6d 7a } //01 00  C:\Program Files\Windows Media Player\defrenlt.wmz
		$a_00_2 = {65 61 73 79 63 6c 69 63 6b 70 6c 75 73 39 } //01 00  easyclickplus9
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 30 2f 6c 67 69 66 2f 90 01 06 2e 67 69 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}