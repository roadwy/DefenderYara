
rule TrojanDownloader_Win32_Renos_gen_CX{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!CX,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 78 3d 30 2f 65 64 3d 30 2f 65 78 3d 30 2f } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 00 00 } //01 00 
		$a_01_2 = {79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 6d 61 79 20 62 65 20 69 6e 66 65 63 74 65 64 } //01 00 
		$a_01_3 = {53 65 63 75 72 69 74 79 20 77 61 72 6e 69 6e 67 00 } //01 00 
		$a_01_4 = {43 6c 69 63 6b 20 68 65 72 65 20 74 6f 20 6c 65 61 72 6e 20 6d 6f 72 65 2e } //00 00 
	condition:
		any of ($a_*)
 
}