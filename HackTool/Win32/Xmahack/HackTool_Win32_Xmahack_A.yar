
rule HackTool_Win32_Xmahack_A{
	meta:
		description = "HackTool:Win32/Xmahack.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 20 43 68 65 61 74 } //1 Inject Cheat
		$a_01_1 = {58 00 6d 00 61 00 68 00 6f 00 2e 00 76 00 62 00 70 00 } //1 Xmaho.vbp
		$a_01_2 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 73 00 61 00 6c 00 61 00 68 00 } //1 Password salah
		$a_01_3 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 57 00 72 00 69 00 74 00 65 00 20 00 44 00 4c 00 4c 00 20 00 74 00 6f 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 21 00 } //1 Failed to Write DLL to Process!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}