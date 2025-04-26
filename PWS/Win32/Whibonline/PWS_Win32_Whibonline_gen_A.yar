
rule PWS_Win32_Whibonline_gen_A{
	meta:
		description = "PWS:Win32/Whibonline.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {59 42 5f 4f 6e 6c 69 6e 65 43 6c 69 65 6e 74 00 44 33 44 20 57 69 6e 64 6f 77 } //3 䉙佟汮湩䍥楬湥t㍄⁄楗摮睯
		$a_00_1 = {23 33 32 37 37 30 } //1 #32770
		$a_01_2 = {47 65 74 50 61 73 73 } //1 GetPass
		$a_01_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_4 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c } //1 MAIL FROM: <
		$a_00_5 = {52 43 50 54 20 54 4f 3a 20 3c } //1 RCPT TO: <
		$a_00_6 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 Explorer.exe
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}