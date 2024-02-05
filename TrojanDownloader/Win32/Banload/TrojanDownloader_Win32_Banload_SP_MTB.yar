
rule TrojanDownloader_Win32_Banload_SP_MTB{
	meta:
		description = "TrojanDownloader:Win32/Banload.SP!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 61 70 70 64 61 74 61 25 5c 77 69 6e 64 6c 6c 2e 65 78 65 } //01 00 
		$a_01_1 = {74 63 70 2e 6e 67 72 6f 6b 2e 69 6f } //01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 54 69 6d 65 20 5a 6f 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}