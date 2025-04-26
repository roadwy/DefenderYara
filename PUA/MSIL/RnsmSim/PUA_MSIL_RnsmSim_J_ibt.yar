
rule PUA_MSIL_RnsmSim_J_ibt{
	meta:
		description = "PUA:MSIL/RnsmSim.J!ibt,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 65 72 2e 65 78 65 } //1 Starter.exe
		$a_01_1 = {4f 62 66 75 73 63 61 74 65 64 42 79 41 67 69 6c 65 44 6f 74 4e 65 74 41 74 74 72 69 62 75 74 65 } //1 ObfuscatedByAgileDotNetAttribute
		$a_01_2 = {32 34 37 33 66 62 64 65 2d 30 63 32 34 2d 34 31 61 30 2d 62 62 30 33 2d 34 66 66 62 64 36 39 65 37 38 63 36 } //1 2473fbde-0c24-41a0-bb03-4ffbd69e78c6
		$a_01_3 = {57 69 6e 64 6f 77 73 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 43 6f 6e 74 65 78 74 } //1 WindowsImpersonationContext
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}