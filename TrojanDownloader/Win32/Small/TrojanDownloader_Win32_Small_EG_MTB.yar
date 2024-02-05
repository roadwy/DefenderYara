
rule TrojanDownloader_Win32_Small_EG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb c2 0c 00 55 8b ec 81 ec 38 08 } //03 00 
		$a_81_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //03 00 
		$a_81_2 = {47 65 74 54 65 6d 70 50 61 74 68 57 46 69 6c 65 53 69 7a 65 } //03 00 
		$a_81_3 = {55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 } //03 00 
		$a_81_4 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 57 } //00 00 
	condition:
		any of ($a_*)
 
}