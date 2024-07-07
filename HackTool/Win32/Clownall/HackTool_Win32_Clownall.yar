
rule HackTool_Win32_Clownall{
	meta:
		description = "HackTool:Win32/Clownall,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 57 7c 74 63 68 2d 44 6f 63 74 30 72 2d } //1 -W|tch-Doct0r-
		$a_01_1 = {41 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 56 00 42 00 39 00 38 00 5c 00 56 00 42 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 43 00 6c 00 6f 00 77 00 6e 00 20 00 43 00 61 00 6c 00 6c 00 5c 00 43 00 6c 00 6f 00 77 00 6e 00 20 00 43 00 61 00 6c 00 6c 00 2e 00 76 00 62 00 70 00 } //1 A*\AC:\Program Files\Microsoft Visual Studio\VB98\VB Projects\Clown Call\Clown Call.vbp
		$a_01_2 = {44 00 69 00 61 00 6c 00 69 00 6e 00 67 00 } //1 Dialing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}