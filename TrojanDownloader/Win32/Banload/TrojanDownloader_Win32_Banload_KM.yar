
rule TrojanDownloader_Win32_Banload_KM{
	meta:
		description = "TrojanDownloader:Win32/Banload.KM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 32 72 65 6c 72 66 6b 73 61 64 76 } //01 00 
		$a_01_1 = {4d 65 6e 73 61 67 65 6e 73 20 64 65 20 65 72 72 6f } //01 00 
		$a_01_2 = {61 72 71 75 69 76 6f 62 6f 6c } //01 00 
		$a_01_3 = {47 62 50 6c 75 67 69 6e 2e 65 78 65 } //01 00 
		$a_01_4 = {2f 45 78 70 6c 6f 72 65 72 2e 6a 73 } //00 00 
	condition:
		any of ($a_*)
 
}