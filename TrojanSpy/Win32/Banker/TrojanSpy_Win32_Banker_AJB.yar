
rule TrojanSpy_Win32_Banker_AJB{
	meta:
		description = "TrojanSpy:Win32/Banker.AJB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {59 00 55 00 51 00 4c 00 32 00 33 00 4b 00 4c 00 32 00 33 00 44 00 46 00 39 00 30 00 57 00 49 00 35 00 45 00 31 00 4a 00 41 00 53 00 } //10 YUQL23KL23DF90WI5E1JAS
		$a_00_1 = {62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 } //1 bradesco
		$a_01_2 = {6d 61 64 44 69 73 41 73 6d } //1 madDisAsm
		$a_01_3 = {4d 6f 75 73 65 48 6f 6f 6b 50 72 6f 63 } //1 MouseHookProc
		$a_00_4 = {73 63 72 65 65 6e 73 68 6f 74 } //1 screenshot
		$a_00_5 = {43 61 69 78 61 } //1 Caixa
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}