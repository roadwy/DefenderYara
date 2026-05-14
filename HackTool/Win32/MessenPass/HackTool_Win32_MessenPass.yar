
rule HackTool_Win32_MessenPass{
	meta:
		description = "HackTool:Win32/MessenPass,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 73 70 61 73 73 5c 63 6f 6d 6d 61 6e 64 2d 6c 69 6e 65 5c 6d 73 70 61 73 73 2e 70 64 62 } //2 \mspass\command-line\mspass.pdb
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 4d 65 73 73 65 6e 50 61 73 73 } //1 Software\NirSoft\MessenPass
		$a_01_2 = {2e 61 69 6d 2e 73 65 73 73 69 6f 6e 2e 70 61 73 73 77 6f 72 64 } //1 .aim.session.password
		$a_01_3 = {73 74 61 62 75 6c 61 72 } //1 stabular
		$a_01_4 = {73 6b 65 65 70 61 73 73 74 } //1 skeepasst
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}