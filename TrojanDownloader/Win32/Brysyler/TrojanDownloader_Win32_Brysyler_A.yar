
rule TrojanDownloader_Win32_Brysyler_A{
	meta:
		description = "TrojanDownloader:Win32/Brysyler.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {f3 ab 8a 06 2c ?? 6a 01 88 44 24 ?? 8d 44 24 ?? 8d 4c 24 ?? 50 51 e8 ?? ?? ?? ?? 8a 46 ?? 83 c4 0c 46 84 c0 75 de } //3
		$a_03_1 = {3c 42 52 3e [0-0a] 3d 3d 63 68 [0-0a] 63 68 3d 3d } //1
		$a_03_2 = {75 70 67 72 [0-05] 2e 68 74 6d [0-15] 77 77 77 2e 00 } //1
		$a_01_3 = {5c 77 69 6e 73 79 73 33 32 2e 74 78 74 } //1 \winsys32.txt
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}