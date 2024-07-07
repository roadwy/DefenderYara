
rule VirTool_Win32_Wovdnut_B_dha{
	meta:
		description = "VirTool:Win32/Wovdnut.B!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 20 75 73 61 67 65 3a 20 6c 6f 61 64 65 72 20 3c 62 69 6e 66 69 6c 65 3e } //1 [ usage: loader <binfile>
		$a_01_1 = {57 53 63 72 69 70 74 3a 3a 53 74 64 45 72 72 } //1 WScript::StdErr
		$a_01_2 = {49 43 6f 72 52 75 6e 74 69 6d 65 48 6f 73 74 3a 3a 43 72 65 61 74 65 44 6f 6d 61 69 6e 28 22 25 77 73 22 29 } //1 ICorRuntimeHost::CreateDomain("%ws")
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 72 6f 6d 48 54 54 50 } //1 DownloadFromHTTP
		$a_01_4 = {43 6f 70 79 69 6e 67 20 25 69 20 62 79 74 65 73 20 6f 66 20 61 73 73 65 6d 62 6c 79 20 74 6f 20 73 61 66 65 20 61 72 72 61 79 } //1 Copying %i bytes of assembly to safe array
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}