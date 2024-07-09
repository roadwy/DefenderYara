
rule TrojanSpy_Win32_Aibatook_A{
	meta:
		description = "TrojanSpy:Win32/Aibatook.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {61 69 6b 6f 74 6f 62 61 [0-10] 6c 6f 67 69 6e 50 61 73 73 77 6f 72 64 } //1
		$a_02_1 = {3f 43 61 72 64 4e 75 6d 3d [0-60] 26 4c 6f 67 69 6e 50 61 73 73 3d [0-10] 26 50 61 79 50 61 73 73 3d } //2
		$a_02_2 = {3f 4d 41 43 3d [0-10] 26 56 45 52 3d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2+(#a_02_2  & 1)*1) >=4
 
}