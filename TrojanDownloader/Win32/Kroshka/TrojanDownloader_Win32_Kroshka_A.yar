
rule TrojanDownloader_Win32_Kroshka_A{
	meta:
		description = "TrojanDownloader:Win32/Kroshka.A,SIGNATURE_TYPE_PEHSTR,33 00 33 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 62 61 62 79 6e 6f 74 2f } //10 /babynot/
		$a_01_1 = {25 75 25 64 25 75 25 64 } //10 %u%d%u%d
		$a_01_2 = {78 73 78 73 6d 78 61 78 2e 65 78 65 } //10 xsxsmxax.exe
		$a_01_3 = {25 73 25 73 25 73 3f 25 73 3d 25 73 } //10 %s%s%s?%s=%s
		$a_01_4 = {49 58 58 50 4c 4f 52 45 2e 45 58 45 } //10 IXXPLORE.EXE
		$a_01_5 = {43 72 65 61 7a 65 50 72 6f 63 65 73 73 41 } //10 CreazeProcessA
		$a_01_6 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 41 00 6c 00 6c 00 20 00 52 00 69 00 67 00 68 00 74 00 73 00 20 00 52 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 } //1 Microsoft Corporation All Rights Reserved
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1) >=51
 
}