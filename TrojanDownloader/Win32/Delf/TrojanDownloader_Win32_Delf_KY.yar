
rule TrojanDownloader_Win32_Delf_KY{
	meta:
		description = "TrojanDownloader:Win32/Delf.KY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 55 68 90 01 04 64 ff 30 64 89 20 85 db 74 90 01 01 53 8b 45 f0 50 e8 90 01 04 85 c0 74 90 00 } //01 00 
		$a_00_1 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00 
		$a_02_2 = {6d 79 69 65 90 02 08 43 6e 4e 75 6f 49 45 2e 65 78 65 90 00 } //01 00 
		$a_00_3 = {2f 56 45 52 59 53 49 4c 45 4e 54 } //01 00 
		$a_00_4 = {4b 75 6f 44 6f 75 53 65 74 75 70 } //00 00 
	condition:
		any of ($a_*)
 
}