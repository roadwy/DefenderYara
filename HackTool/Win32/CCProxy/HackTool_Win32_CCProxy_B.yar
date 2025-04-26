
rule HackTool_Win32_CCProxy_B{
	meta:
		description = "HackTool:Win32/CCProxy.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 65 72 3a 20 43 43 50 72 6f 78 79 } //1 Server: CCProxy
		$a_02_1 = {50 72 6f 78 79 2d 61 67 65 6e 74 3a 20 (77 6f 72 6b 73 6e 74|43 43 50 72 6f 78 79) } //1
		$a_00_2 = {72 65 6d 6f 74 65 63 6f 6e 74 72 6f 6c } //1 remotecontrol
		$a_00_3 = {70 72 6f 78 79 2e 74 78 74 } //1 proxy.txt
		$a_00_4 = {43 43 50 72 6f 78 79 00 5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 25 73 00 2d 72 65 73 65 74 00 00 2d 75 70 64 61 74 65 00 2d 73 65 72 76 69 63 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}