
rule VirTool_Win32_CeeInject_gen_FG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 46 28 03 46 34 } //1
		$a_01_1 = {8b 56 50 8b 46 34 } //1
		$a_03_2 = {07 00 01 00 90 09 04 00 c7 44 24 90 00 } //1
		$a_00_3 = {44 3a 5c 42 75 69 6c 64 53 63 72 69 70 74 2e 4e 45 54 5c 63 32 70 61 74 63 68 64 78 31 31 5c 70 63 5c 42 75 69 6c 64 5c 42 69 6e 33 32 5c 43 72 79 73 69 73 32 2e 70 64 62 } //-10 D:\BuildScript.NET\c2patchdx11\pc\Build\Bin32\Crysis2.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*-10) >=3
 
}