
rule VirTool_Win32_VBInject_gen_FE{
	meta:
		description = "VirTool:Win32/VBInject.gen!FE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //1 RtlMoveMemory
		$a_00_1 = {70 68 6f 6e 65 47 65 74 48 6f 6f 6b 53 77 69 74 63 68 } //1 phoneGetHookSwitch
		$a_00_2 = {44 64 65 44 69 73 63 6f 6e 6e 65 63 74 4c 69 73 74 } //1 DdeDisconnectList
		$a_00_3 = {22 6f 4e 22 } //1 "oN"
		$a_00_4 = {22 73 65 59 22 } //1 "seY"
		$a_00_5 = {22 65 78 65 2e } //1 "exe.
		$a_01_6 = {7c 00 7c 00 7c 00 7c 00 51 00 52 00 45 00 42 00 54 00 4e 00 46 00 46 00 6a 00 51 00 7a 00 67 00 6b 00 4a 00 } //1 ||||QREBTNFFjQzgkJ
		$a_01_7 = {7c 00 7c 00 4d 00 31 00 55 00 42 00 78 00 30 00 51 00 66 00 64 00 31 00 54 00 45 00 35 00 55 00 53 00 58 00 39 00 6c 00 54 00 50 00 31 00 30 00 51 00 50 00 4a 00 46 00 55 00 } //1 ||M1UBx0Qfd1TE5USX9lTP10QPJFU
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}