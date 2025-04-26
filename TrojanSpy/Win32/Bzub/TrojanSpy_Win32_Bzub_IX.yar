
rule TrojanSpy_Win32_Bzub_IX{
	meta:
		description = "TrojanSpy:Win32/Bzub.IX,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 67 65 6e 74 5f 64 71 2e 64 6c 6c } //3 agent_dq.dll
		$a_01_1 = {46 74 70 4f 70 65 6e 46 69 6c 65 41 } //2 FtpOpenFileA
		$a_01_2 = {53 48 44 65 6c 65 74 65 4b 65 79 41 } //2 SHDeleteKeyA
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //2 ShellExecuteA
		$a_01_4 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 4d 79 20 4f 66 66 69 63 65 20 41 64 64 69 6e 20 62 75 69 6c 74 20 77 69 74 68 20 2e 4e 65 74 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e } //1 <description>My Office Addin built with .Net</description>
		$a_01_5 = {46 74 70 43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 FtpCreateDirectoryA
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}