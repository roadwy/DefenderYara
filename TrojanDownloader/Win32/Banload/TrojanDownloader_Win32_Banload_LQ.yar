
rule TrojanDownloader_Win32_Banload_LQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.LQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 70 65 72 66 74 65 6d 70 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {4d 73 6e 6c 2e 6a 70 67 00 } //01 00 
		$a_01_2 = {4d 73 6e 73 2e 6a 70 67 00 } //01 00 
		$a_01_3 = {2e 74 74 74 00 00 00 00 ff ff ff ff 04 00 00 00 2e 64 64 64 00 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}