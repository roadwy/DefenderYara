
rule TrojanDownloader_Win32_Swizzor_gen_L{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 66 69 6c 65 2e 70 68 70 3f 66 69 6c 65 3d } //02 00 
		$a_01_1 = {43 34 44 4c 20 4d 65 64 69 61 } //02 00 
		$a_01_2 = {26 61 66 66 69 64 5f 74 72 3d } //02 00 
		$a_01_3 = {5c 6d 69 6e 69 6d 65 2e 65 78 65 } //01 00 
		$a_01_4 = {5c 48 74 6d 6c 43 6f 6e 74 72 6f 6c 2e 64 6c 6c } //01 00 
		$a_01_5 = {5c 68 74 6d 6c 63 6f 6e 74 72 6f 6c 33 } //01 00 
		$a_01_6 = {69 6e 73 74 61 6c 6c 5f 63 6f 6d 70 6c 65 74 65 2e 70 68 70 3f 41 70 70 50 72 6f 67 72 61 6d 3d } //01 00 
		$a_01_7 = {2e 64 6c 6c 3a 3a 50 61 79 46 75 6e 63 28 } //00 00 
	condition:
		any of ($a_*)
 
}