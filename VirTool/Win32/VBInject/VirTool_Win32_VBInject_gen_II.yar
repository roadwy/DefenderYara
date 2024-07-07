
rule VirTool_Win32_VBInject_gen_II{
	meta:
		description = "VirTool:Win32/VBInject.gen!II,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 69 00 64 00 65 00 70 00 72 00 6f 00 63 00 2e 00 73 00 79 00 73 00 } //2 hideproc.sys
		$a_01_1 = {52 44 47 53 6f 46 54 } //2 RDGSoFT
		$a_01_2 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } //1 EncryptString
		$a_01_3 = {77 00 32 00 31 00 6d 00 30 00 31 00 6d 00 37 00 77 00 6e 00 71 00 77 00 } //3 w21m01m7wnqw
		$a_01_4 = {2a 00 56 00 4d 00 57 00 41 00 52 00 45 00 2a 00 } //2 *VMWARE*
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=10
 
}