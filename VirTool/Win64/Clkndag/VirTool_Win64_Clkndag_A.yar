
rule VirTool_Win64_Clkndag_A{
	meta:
		description = "VirTool:Win64/Clkndag.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 67 65 74 43 75 72 72 65 6e 74 55 73 65 72 } //1 main.getCurrentUser
		$a_01_1 = {43 6c 6f 61 6b 4e 44 61 67 67 65 72 43 32 } //1 CloakNDaggerC2
		$a_01_2 = {72 75 6e 43 6f 6d 6d 61 6e 64 } //1 runCommand
		$a_01_3 = {73 79 73 63 61 6c 6c 2e 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 syscall.GetCurrentProcess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}