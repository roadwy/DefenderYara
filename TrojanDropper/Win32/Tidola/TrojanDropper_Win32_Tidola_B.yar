
rule TrojanDropper_Win32_Tidola_B{
	meta:
		description = "TrojanDropper:Win32/Tidola.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 63 74 3d 26 64 31 30 3d 25 73 26 64 38 30 3d 25 64 00 } //1
		$a_01_1 = {63 7e 24 7e 6d 64 20 7e 24 7e 2f 63 20 7e 24 7e 64 65 7e 24 7e 6c 20 25 73 00 } //1 繣縤摭縠縤振縠縤敤⑾汾┠s
		$a_01_2 = {5c 64 72 69 7e 24 7e 76 65 72 73 5c 65 7e 24 7e 74 63 5c 68 6f 73 7e 24 7e 74 73 00 } //1 摜楲⑾百牥屳繥縤捴桜獯⑾瑾s
		$a_01_3 = {25 73 7e 24 7e 25 73 7e 24 7e 2a 7e 24 7e 2e 64 6c 6c } //1 %s~$~%s~$~*~$~.dll
		$a_01_4 = {65 78 70 6c 7e 24 7e 6f 72 65 72 2e 65 78 65 } //1 expl~$~orer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}