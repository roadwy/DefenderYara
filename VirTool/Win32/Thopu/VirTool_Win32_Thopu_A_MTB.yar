
rule VirTool_Win32_Thopu_A_MTB{
	meta:
		description = "VirTool:Win32/Thopu.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 76 65 72 73 65 2d 73 68 65 6c 6c 2f 70 6b 67 2e 69 6e 69 74 } //1 reverse-shell/pkg.init
		$a_01_1 = {72 65 76 65 72 73 65 2d 73 68 65 6c 6c 2f 63 6d 64 2f 63 6c 69 65 6e 74 2f 63 6c 69 65 6e 74 2e 67 6f } //1 reverse-shell/cmd/client/client.go
		$a_01_2 = {61 64 65 64 61 79 6f 2f 72 65 76 65 72 73 65 2d 73 68 65 6c 6c 2f 70 6b 67 2e 53 68 65 6c 6c 4f 75 74 } //1 adedayo/reverse-shell/pkg.ShellOut
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}