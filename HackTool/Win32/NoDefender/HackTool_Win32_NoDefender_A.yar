
rule HackTool_Win32_NoDefender_A{
	meta:
		description = "HackTool:Win32/NoDefender.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 73 63 5f 70 72 6f 78 79 2e 65 78 65 } //wsc_proxy.exe  1
		$a_80_1 = {6c 6f 61 64 69 6e 67 20 74 68 65 20 77 73 63 5f 70 72 6f 78 79 } //loading the wsc_proxy  1
		$a_80_2 = {6e 6f 2d 64 65 66 65 6e 64 65 72 2d 6c 6f 61 64 65 72 2e 70 64 62 } //no-defender-loader.pdb  1
		$a_80_3 = {72 75 6e 61 73 73 76 63 20 2f 72 70 63 73 65 72 76 65 72 } //runassvc /rpcserver  1
		$a_80_4 = {67 69 74 68 75 62 2e 63 6f 6d 2f 65 73 33 6e 31 6e 2f 6e 6f 2d 64 65 66 65 6e 64 65 72 } //github.com/es3n1n/no-defender  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}