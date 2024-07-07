
rule VirTool_Win32_Pheweq_A_MTB{
	meta:
		description = "VirTool:Win32/Pheweq.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 53 48 2f 66 69 6e 61 6c 2e 67 6f } //1 GoSH/final.go
		$a_01_1 = {77 69 6e 74 72 6d 76 74 65 2f 47 6f 53 48 } //1 wintrmvte/GoSH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}