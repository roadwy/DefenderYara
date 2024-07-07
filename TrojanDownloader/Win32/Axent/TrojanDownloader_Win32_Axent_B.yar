
rule TrojanDownloader_Win32_Axent_B{
	meta:
		description = "TrojanDownloader:Win32/Axent.B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 78 6f 63 65 73 73 33 32 4e 65 78 74 } //5 Pxocess32Next
		$a_01_1 = {43 72 65 61 71 65 50 72 6f 63 65 73 73 41 } //5 CreaqeProcessA
		$a_01_2 = {75 7a 6c 6d 6f 6e 2e 64 6c 6c } //5 uzlmon.dll
		$a_01_3 = {50 58 6f 63 65 73 73 33 32 46 69 72 73 74 } //5 PXocess32First
		$a_01_4 = {49 58 58 50 4c 4f 52 45 2e 45 58 45 } //2 IXXPLORE.EXE
		$a_01_5 = {71 73 78 73 6d 78 61 71 2e 45 58 45 } //2 qsxsmxaq.EXE
		$a_01_6 = {2f 62 61 62 79 6e 6f 74 2f } //2 /babynot/
		$a_01_7 = {50 6f 69 26 65 72 28 } //1 Poi&er(
		$a_01_8 = {25 75 25 64 25 75 25 64 } //2 %u%d%u%d
		$a_01_9 = {25 73 25 73 25 73 3f 25 73 3d 25 73 } //2 %s%s%s?%s=%s
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=21
 
}