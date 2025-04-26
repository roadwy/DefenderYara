
rule TrojanDropper_Win32_VB_BC{
	meta:
		description = "TrojanDropper:Win32/VB.BC,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 4a 00 3a 00 5c 00 4d 00 41 00 53 00 54 00 45 00 52 00 5c 00 61 00 64 00 5f 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72 00 5c 00 6d 00 6f 00 79 00 2e 00 65 00 78 00 65 00 5c 00 62 00 61 00 6c 00 76 00 61 00 6e 00 6b 00 61 00 5c 00 5a 00 41 00 47 00 2e 00 76 00 62 00 70 00 } //1 AJ:\MASTER\ad_compiler\moy.exe\balvanka\ZAG.vbp
		$a_01_1 = {76 00 76 00 67 00 65 00 6f 00 77 00 62 00 76 00 2e 00 65 00 78 00 65 00 } //1 vvgeowbv.exe
		$a_01_2 = {6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 62 00 69 00 6e 00 } //1 loader.bin
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 } //1 GetSystemDirectory
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //10 C:\Program Files\Microsoft Visual Studio\VB98\VB6.OLB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=14
 
}