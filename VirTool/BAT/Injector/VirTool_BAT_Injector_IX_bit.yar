
rule VirTool_BAT_Injector_IX_bit{
	meta:
		description = "VirTool:BAT/Injector.IX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 91 61 9c 11 ?? 17 58 13 ?? 11 ?? 11 ?? 31 } //1
		$a_00_1 = {09 4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 00 } //1
		$a_03_2 = {2e 64 6c 6c 00 53 74 72 43 6d 70 4c 6f 67 69 63 61 6c 57 00 73 31 00 73 32 00 73 68 6c 77 61 70 69 2e 64 6c 6c 00 5f 41 36 [0-50] 5f 41 37 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}