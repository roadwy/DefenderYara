
rule HackTool_Win32_PasswordRecovery_AMTB{
	meta:
		description = "HackTool:Win32/PasswordRecovery!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 53 65 63 75 72 69 74 79 58 70 6c 6f 64 65 64 2e 63 6f 6d } //www.SecurityXploded.com  1
		$a_80_1 = {4e 65 74 77 6f 72 6b 50 61 73 73 77 6f 72 64 44 65 63 72 79 70 74 6f 72 2e 65 78 65 } //NetworkPasswordDecryptor.exe  1
		$a_80_2 = {77 77 77 2e 50 61 73 73 77 6f 72 64 46 6f 72 65 6e 73 69 63 73 2e 63 6f 6d } //www.PasswordForensics.com  1
		$a_80_3 = {43 6f 6e 74 61 63 74 40 53 65 63 75 72 69 74 79 58 70 6c 6f 64 65 64 2e 63 6f 6d } //Contact@SecurityXploded.com  1
		$a_80_4 = {4e 65 74 77 6f 72 6b 50 61 73 73 77 6f 72 64 44 65 63 72 79 70 74 6f 72 } //NetworkPasswordDecryptor  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}