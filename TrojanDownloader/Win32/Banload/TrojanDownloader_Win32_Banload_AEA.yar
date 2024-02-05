
rule TrojanDownloader_Win32_Banload_AEA{
	meta:
		description = "TrojanDownloader:Win32/Banload.AEA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {32 30 31 33 31 37 33 32 31 33 31 37 32 34 37 33 31 33 33 31 37 } //01 00 
		$a_00_1 = {32 30 36 33 32 32 33 32 36 33 32 32 32 35 32 33 32 32 33 31 37 33 31 30 33 32 31 } //01 00 
		$a_00_2 = {54 66 72 4c 6f 6c 69 74 61 } //01 00 
		$a_00_3 = {55 6c 6f 6c 69 74 61 } //01 00 
		$a_01_4 = {66 83 eb 02 66 83 fb 03 76 40 } //00 00 
	condition:
		any of ($a_*)
 
}