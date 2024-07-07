
rule VirTool_BAT_Bladabindi_A{
	meta:
		description = "VirTool:BAT/Bladabindi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {6e 6a 52 41 54 20 44 6f 77 6e 6c 6f 61 65 64 65 72 20 76 } //njRAT Downloaeder v  3
		$a_80_1 = {42 79 20 6e 6a 71 38 } //By njq8  2
		$a_80_2 = {5b 73 74 61 72 74 75 70 5d } //[startup]  1
		$a_80_3 = {5b 6c 69 6e 6b 73 5d } //[links]  1
		$a_80_4 = {5c 73 74 75 62 2e 65 78 65 } //\stub.exe  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}