
rule TrojanSpy_Win32_Trace_A{
	meta:
		description = "TrojanSpy:Win32/Trace.A,SIGNATURE_TYPE_PEHSTR,07 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 54 72 79 00 00 00 00 ff ff ff ff 05 00 00 00 44 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 ff ff ff ff 0a 00 00 00 49 66 20 45 78 69 73 74 20 22 00 00 ff ff ff ff 09 00 00 00 20 47 6f 74 6f 20 54 72 79 00 00 00 } //2
		$a_01_1 = {2f 76 65 72 2e 70 68 70 3f 6e 6f 3d } //2 /ver.php?no=
		$a_01_2 = {00 73 76 63 73 2e 65 78 65 } //2
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 54 72 61 63 65 20 53 65 72 76 69 63 65 } //1 SOFTWARE\Trace Service
		$a_01_5 = {2f 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 } //1 /install /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}