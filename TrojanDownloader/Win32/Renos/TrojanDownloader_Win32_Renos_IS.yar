
rule TrojanDownloader_Win32_Renos_IS{
	meta:
		description = "TrojanDownloader:Win32/Renos.IS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 61 72 6e 69 6e 67 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 76 69 72 75 73 20 21 21 } //01 00  Warning your computer has virus !!
		$a_00_1 = {28 77 69 6e 64 6f 77 2e 73 65 6c 66 20 3d 3d 20 77 69 6e 64 6f 77 2e 74 6f 70 29 } //01 00  (window.self == window.top)
		$a_00_2 = {62 61 63 6b 67 72 6f 75 6e 64 2d 63 6f 6c 6f 72 3a 72 65 64 } //01 00  background-color:red
		$a_00_3 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 55 6e 69 6e 73 74 61 6c 6c 00 57 53 50 53 74 61 72 74 75 70 } //00 00 
	condition:
		any of ($a_*)
 
}