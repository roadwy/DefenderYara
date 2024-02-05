
rule TrojanDownloader_Win32_Cutwail_BP{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //01 00 
		$a_02_1 = {b9 00 24 00 00 8b 35 90 01 04 81 c6 90 01 04 8b fe 51 b9 90 01 04 8b 45 fc d1 c0 89 45 fc e2 f6 59 eb 90 00 } //01 00 
		$a_00_2 = {8b 45 fc 05 01 01 01 00 05 01 01 01 01 89 45 fc 8b 5d fc ac 90 32 c3 90 aa f7 c1 01 00 00 00 74 0b } //00 00 
	condition:
		any of ($a_*)
 
}