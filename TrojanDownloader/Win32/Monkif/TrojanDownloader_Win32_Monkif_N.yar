
rule TrojanDownloader_Win32_Monkif_N{
	meta:
		description = "TrojanDownloader:Win32/Monkif.N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_03_0 = {8a c8 80 e9 90 01 01 30 88 90 01 04 40 3d 90 01 02 00 00 7c ed 90 00 } //2
		$a_01_1 = {75 e1 ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd } //1
		$a_01_2 = {75 d3 8b 45 0c ff 45 fc 8b 4d fc 6b c9 60 8d 34 01 39 1e 75 b8 } //1
		$a_03_3 = {8d 46 fe 83 c4 90 01 01 3d 90 01 04 7c 90 00 } //1
		$a_03_4 = {83 c4 30 46 8d 46 fe 3d 90 01 04 7c 90 00 } //1
		$a_01_5 = {58 b9 0f 00 00 00 51 50 cb } //1
		$a_01_6 = {50 58 6f 63 65 73 73 } //1 PXocess
		$a_01_7 = {50 72 30 63 65 73 73 } //1 Pr0cess
		$a_01_8 = {50 72 6f 33 65 73 73 } //1 Pro3ess
		$a_01_9 = {43 42 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CBeateToolhelp32Snapshot
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}