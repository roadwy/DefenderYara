
rule TrojanDownloader_Win32_Zlob_VWX{
	meta:
		description = "TrojanDownloader:Win32/Zlob.VWX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 fc fe ff ff 47 c6 85 fd fe ff ff 45 c6 85 fe fe ff ff 54 } //01 00 
		$a_01_1 = {83 7c 24 08 30 7c 0c 83 7c 24 08 39 7f 05 } //01 00 
		$a_01_2 = {25 73 5c 77 67 76 25 73 25 64 2e 65 78 65 00 } //01 00 
		$a_03_3 = {6a 04 83 c7 0c 57 ff 74 24 24 ff 15 90 01 04 8b 84 24 30 01 00 00 53 8d 4c 24 1c 51 83 c0 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Zlob_VWX_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob.VWX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 f0 fe ff ff 47 c6 85 f1 fe ff ff 45 c6 85 f2 fe ff ff 54 } //01 00 
		$a_01_1 = {6d 67 72 74 2e 64 6c 6c 00 63 6f 6f 6c 00 66 65 65 64 00 70 6c 65 6d 00 } //01 00  杭瑲搮汬挀潯l敦摥瀀敬m
		$a_01_2 = {5f 52 45 44 44 5f 00 } //01 00 
		$a_01_3 = {25 73 5c 6a 65 65 25 73 25 64 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}