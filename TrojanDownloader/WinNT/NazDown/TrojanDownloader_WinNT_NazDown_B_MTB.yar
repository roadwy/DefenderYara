
rule TrojanDownloader_WinNT_NazDown_B_MTB{
	meta:
		description = "TrojanDownloader:WinNT/NazDown.B!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {67 65 74 52 75 6e 74 69 6d 65 90 02 32 2e 63 6f 6d 2f 6e 61 7a 69 6f 6e 61 6c 65 2e 6a 70 67 90 00 } //01 00 
		$a_00_1 = {6e 61 7a 69 6f 6e 61 6c 65 2e 65 78 65 01 00 04 6f 70 65 6e } //01 00 
		$a_00_2 = {72 65 61 64 01 00 25 72 75 6e 64 6c 6c 33 32 20 75 72 6c 2e 64 6c 6c 2c 46 69 6c 65 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } //01 00 
		$a_00_3 = {50 72 65 76 69 64 65 6e 7a 61 } //01 00 
		$a_00_4 = {2f 68 6f 6d 65 2e 68 74 6d 01 00 0e 6a 61 76 61 2e 69 6f 2e 74 6d 70 64 69 72 } //00 00 
	condition:
		any of ($a_*)
 
}