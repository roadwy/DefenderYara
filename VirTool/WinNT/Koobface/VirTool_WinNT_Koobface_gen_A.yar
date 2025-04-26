
rule VirTool_WinNT_Koobface_gen_A{
	meta:
		description = "VirTool:WinNT/Koobface.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 61 6e 66 63 } //1 hanfc
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 46 00 52 00 00 00 } //1
		$a_01_2 = {2d 90 01 22 00 74 58 83 e8 04 74 46 83 e8 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}