
rule TrojanDownloader_Win32_Garveep_C{
	meta:
		description = "TrojanDownloader:Win32/Garveep.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {8a 0c 2e 32 d2 8d 44 24 11 bf 08 00 00 00 84 48 ff 8a 18 74 04 0a d3 eb 04 f6 d3 22 d3 83 c0 02 4f 75 eb 8b 44 24 24 88 14 2e 46 3b f0 7c d1 8b fd } //03 00 
		$a_03_1 = {3d 97 01 00 00 0f 84 90 01 04 68 00 04 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}