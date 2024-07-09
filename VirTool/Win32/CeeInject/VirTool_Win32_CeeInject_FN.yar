
rule VirTool_Win32_CeeInject_FN{
	meta:
		description = "VirTool:Win32/CeeInject.FN,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 b9 ff 00 00 00 f7 f9 89 74 24 ?? 42 3b de 76 ?? 8b 44 24 ?? 8a 0c 38 80 e9 ?? 32 ca ff 44 24 ?? 88 0c 38 39 5c 24 ?? 72 } //1
		$a_01_1 = {7c 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 7c 43 72 65 61 74 65 50 72 6f 63 65 73 73 57 7c 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 7c 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 7c 52 65 73 75 6d 65 54 68 72 65 61 64 7c 46 69 6e 64 52 65 73 6f 75 72 63 65 41 7c 4c 6f 61 64 52 65 73 6f 75 72 63 65 7c 53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 7c } //1 |WriteProcessMemory|CreateProcessW|SetThreadContext|GetThreadContext|ResumeThread|FindResourceA|LoadResource|SizeofResource|
		$a_01_2 = {00 35 39 32 30 71 68 62 30 77 33 6a 66 71 61 77 32 33 00 00 00 25 64 00 00 7c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}