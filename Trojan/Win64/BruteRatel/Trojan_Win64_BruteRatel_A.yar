
rule Trojan_Win64_BruteRatel_A{
	meta:
		description = "Trojan:Win64/BruteRatel.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 63 6c 73 69 64 5c 7b 39 66 63 38 65 35 31 30 2d 61 32 37 63 2d 34 62 33 62 2d 62 39 61 33 2d 62 66 36 35 66 30 30 32 35 36 61 38 7d 5c 69 6e 70 72 6f 63 73 65 72 76 65 72 33 32 } //software\classes\clsid\{9fc8e510-a27c-4b3b-b9a3-bf65f00256a8}\inprocserver32  10
		$a_80_1 = {5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2f 65 2c 3a 3a 7b 39 66 63 38 65 35 31 30 2d 61 32 37 63 2d 34 62 33 62 2d 62 39 61 33 2d 62 66 36 35 66 30 30 32 35 36 61 38 7d } //\windows\explorer.exe /e,::{9fc8e510-a27c-4b3b-b9a3-bf65f00256a8}  10
		$a_80_2 = {25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 61 70 70 73 5c 64 61 74 61 6c 61 79 65 72 2e 64 6c 6c } //%localappdata%\microsoft\windowsapps\datalayer.dll  2
		$a_80_3 = {77 69 72 65 73 68 61 72 6b 2e 65 78 65 } //wireshark.exe  1
		$a_80_4 = {64 65 73 6b 74 6f 70 2d } //desktop-  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=22
 
}