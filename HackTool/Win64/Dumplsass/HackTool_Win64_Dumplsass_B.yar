
rule HackTool_Win64_Dumplsass_B{
	meta:
		description = "HackTool:Win64/Dumplsass.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 41 00 7a 00 75 00 72 00 65 00 57 00 61 00 74 00 73 00 6f 00 6e 00 5c 00 30 00 5c 00 70 00 72 00 6f 00 63 00 64 00 75 00 6d 00 70 00 } //-2 \ProgramData\Microsoft\AzureWatson\0\procdump
		$a_02_1 = {2d 00 6a 00 20 00 90 02 04 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00 90 00 } //-2
		$a_00_2 = {5c 00 70 00 72 00 6f 00 63 00 64 00 75 00 6d 00 70 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //2 \procdump64.exe
		$a_00_3 = {2d 00 6d 00 } //1 -m
		$a_00_4 = {2f 00 6d 00 } //1 /m
	condition:
		((#a_00_0  & 1)*-2+(#a_02_1  & 1)*-2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}
rule HackTool_Win64_Dumplsass_B_2{
	meta:
		description = "HackTool:Win64/Dumplsass.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 69 74 63 65 6a 6e 49 79 42 70 6d 75 44 7a 74 6b 4d } //1 noitcejnIyBpmuDztkM
		$a_01_1 = {64 72 6f 77 73 73 61 50 70 6d 75 44 63 6f 72 50 79 42 70 6d 75 44 7a 74 6b 4d } //1 drowssaPpmuDcorPyBpmuDztkM
		$a_01_2 = {43 44 79 42 70 6d 75 44 7a 74 6b 4d } //1 CDyBpmuDztkM
		$a_01_3 = {65 6c 69 46 6d 61 53 79 42 70 6d 75 44 7a 74 6b 4d } //1 eliFmaSyBpmuDztkM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}