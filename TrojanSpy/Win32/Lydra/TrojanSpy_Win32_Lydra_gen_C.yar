
rule TrojanSpy_Win32_Lydra_gen_C{
	meta:
		description = "TrojanSpy:Win32/Lydra.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //10 FPUMaskValue
		$a_00_2 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //10 UnhookWindowsHookEx
		$a_01_3 = {69 65 63 6f 6d 6e 2e 64 6c 6c 00 00 00 00 57 69 6e 5f 50 72 6f 63 00 } //3
		$a_01_4 = {69 65 63 6f 6d 6e 2e 64 6c 6c 00 00 00 00 47 65 74 41 6e 64 53 65 74 00 } //3
		$a_01_5 = {76 69 61 75 64 2e 64 6c 6c 00 42 65 67 69 6e 57 69 6e 50 72 6f 63 00 } //2
		$a_01_6 = {76 69 61 75 64 2e 64 6c 6c 00 53 74 61 72 74 49 6e 74 72 75 64 69 6e 67 00 } //2
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=35
 
}