
rule TrojanDownloader_Win32_Zlob_gen_CT{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CT,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {35 31 00 51 75 69 63 6b 54 69 6d 65 } //01 00 
		$a_01_1 = {24 73 2f 67 65 74 2e 70 68 70 3f 69 64 3d } //01 00 
		$a_01_2 = {64 20 77 69 74 68 20 61 64 77 61 } //01 00 
		$a_01_3 = {5f 5f 50 4d 5f 4d 49 4e 49 5f 53 54 4f } //00 00 
	condition:
		any of ($a_*)
 
}