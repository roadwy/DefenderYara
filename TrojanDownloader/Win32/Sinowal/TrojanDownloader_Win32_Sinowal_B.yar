
rule TrojanDownloader_Win32_Sinowal_B{
	meta:
		description = "TrojanDownloader:Win32/Sinowal.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 65 76 65 72 66 69 6c 65 00 72 65 76 65 6e 65 6c 69 66 } //01 00 
		$a_01_1 = {83 79 58 05 0f 83 } //01 00 
		$a_00_2 = {81 c9 00 07 00 00 83 f1 40 } //00 00 
	condition:
		any of ($a_*)
 
}