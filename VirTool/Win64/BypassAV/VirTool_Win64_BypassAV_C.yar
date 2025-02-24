
rule VirTool_Win64_BypassAV_C{
	meta:
		description = "VirTool:Win64/BypassAV.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 79 70 61 73 73 45 44 52 2d 41 56 2f 73 79 73 63 61 6c 6c 2e 67 6f } //1 /bypassEDR-AV/syscall.go
		$a_01_1 = {52 65 74 75 72 6e 53 68 65 6c 6c 63 6f 64 65 } //1 ReturnShellcode
		$a_01_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_3 = {4d 41 4b 45 49 4e 54 52 45 53 4f 55 52 43 45 } //1 MAKEINTRESOURCE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}