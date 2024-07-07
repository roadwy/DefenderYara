
rule TrojanDropper_Win32_Zlob{
	meta:
		description = "TrojanDropper:Win32/Zlob,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 63 73 76 00 26 fe 84 85 8d ff 6c 3d 73 68 62 26 73 75 62 95 63 d3 6e 5e 4c 68 18 42 17 3e 64 } //1
		$a_01_1 = {12 d8 66 6f 2f 67 65 c2 75 70 64 85 2e 70 68 70 } //1
		$a_01_2 = {45 6e 5a 50 18 7c c0 3e 47 65 72 9f 2e 44 4c 4c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}