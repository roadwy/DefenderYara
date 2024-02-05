
rule TrojanDownloader_Win32_Seraph_PAAP_MTB{
	meta:
		description = "TrojanDownloader:Win32/Seraph.PAAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 72 70 2e 6d 79 6c 32 33 2e 63 6f 6d 2f 61 70 69 2e 6a 73 70 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00 
		$a_01_2 = {69 20 61 6d 20 61 76 70 } //01 00 
		$a_01_3 = {3a 2f 2f 6c 69 76 65 2e 6d 79 6c 32 33 2e 63 6f 6d 2f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}