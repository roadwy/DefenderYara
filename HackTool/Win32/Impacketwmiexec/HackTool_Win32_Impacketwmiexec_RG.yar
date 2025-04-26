
rule HackTool_Win32_Impacketwmiexec_RG{
	meta:
		description = "HackTool:Win32/Impacketwmiexec.RG,SIGNATURE_TYPE_CMDHSTR_EXT,67 00 67 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //1  /c 
		$a_02_2 = {3e 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-20] 2e 00 74 00 6d 00 70 00 } //100
		$a_00_3 = {20 00 32 00 3e 00 26 00 31 00 } //1  2>&1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*100+(#a_00_3  & 1)*1) >=103
 
}