
rule TrojanDownloader_Win32_Matcash_E{
	meta:
		description = "TrojanDownloader:Win32/Matcash.E,SIGNATURE_TYPE_PEHSTR,23 00 23 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 52 5c 6e 65 78 74 75 70 64 61 74 65 } //1 WR\nextupdate
		$a_01_1 = {57 52 5c 76 65 72 73 69 6f 6e } //1 WR\version
		$a_01_2 = {77 72 2e 6d 63 } //1 wr.mc
		$a_01_3 = {2e 65 78 65 2e 74 6d 70 } //1 .exe.tmp
		$a_01_4 = {70 61 69 64 } //2 paid
		$a_01_5 = {61 66 66 49 44 } //10 affID
		$a_01_6 = {66 69 6e 75 } //10 finu
		$a_01_7 = {26 78 3d 00 26 69 3d 00 26 70 3d 00 26 63 6d 64 3d } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=35
 
}