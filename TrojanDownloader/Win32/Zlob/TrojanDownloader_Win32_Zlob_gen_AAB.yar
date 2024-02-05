
rule TrojanDownloader_Win32_Zlob_gen_AAB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AAB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 31 2e 30 2e 32 35 30 2e 34 37 } //01 00 
		$a_01_1 = {25 73 3f 76 65 72 73 69 6f 6e 3d 25 73 26 63 6e 3d 25 73 26 63 6f 6e 74 79 70 65 3d 25 64 26 70 69 64 3d 25 64 } //01 00 
		$a_01_2 = {43 6c 69 63 6b 4e 75 6d } //01 00 
		$a_01_3 = {25 73 3f 69 64 5f 6e 75 6d 3d 25 64 26 74 65 78 74 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}