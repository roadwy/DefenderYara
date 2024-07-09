
rule Trojan_Win32_Wantvi_F{
	meta:
		description = "Trojan:Win32/Wantvi.F,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 "
		
	strings :
		$a_02_0 = {8a 06 02 07 88 06 46 4f 49 81 ff ?? ?? ?? 00 75 05 bf ?? ?? ?? 00 83 f9 00 74 02 eb e3 c3 } //10
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 69 72 65 63 74 53 68 6f 77 5c 39 63 } //10 SOFTWARE\Microsoft\DirectShow\9c
		$a_00_2 = {2d d0 07 00 00 ba 00 00 00 00 b9 04 00 00 00 f7 f1 ba 00 00 00 00 b9 a0 05 00 00 f7 e1 03 d8 b8 00 00 00 00 } //2
		$a_00_3 = {2d d0 07 00 00 bb 00 00 00 00 ba 00 00 00 00 b9 20 05 08 00 f7 e1 8b d8 b8 00 00 00 00 } //1
		$a_00_4 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_00_5 = {43 6f 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CoCreateInstance
		$a_00_6 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=24
 
}