
rule VirTool_Win32_Injector_gen_CS{
	meta:
		description = "VirTool:Win32/Injector.gen!CS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 3c ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 fc 6a 2d ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8 } //1
		$a_01_1 = {50 72 6f 73 74 61 72 74 5f 43 6c 61 73 73 00 } //1
		$a_01_2 = {45 6e 75 6d 65 72 61 74 65 20 52 75 6e 6e 69 6e 67 20 44 65 76 69 63 65 20 44 72 69 76 65 72 73 00 } //1
		$a_03_3 = {8d 45 fc eb 90 14 eb 90 14 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}