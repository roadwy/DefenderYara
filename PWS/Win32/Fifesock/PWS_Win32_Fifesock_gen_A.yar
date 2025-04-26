
rule PWS_Win32_Fifesock_gen_A{
	meta:
		description = "PWS:Win32/Fifesock.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6e 73 70 72 c7 45 ?? 34 2e 64 6c 66 c7 45 ?? 6c 00 c7 45 ?? 77 73 32 5f c7 45 ?? 33 32 2e 64 66 c7 45 ?? 6c 6c c6 45 ?? 00 c7 45 ?? 77 69 6e 69 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 ?? ?? 05 ?? 6a 00 ff 15 [0-0c] 51 50 89 86 ?? 00 00 00 e8 ?? ?? ?? ?? 8b ?? ?? 00 00 00 [0-03] c6 ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}