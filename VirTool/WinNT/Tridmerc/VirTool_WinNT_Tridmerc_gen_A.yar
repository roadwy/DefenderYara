
rule VirTool_WinNT_Tridmerc_gen_A{
	meta:
		description = "VirTool:WinNT/Tridmerc.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 04 80 7b 2a 57 8b 7d 24 89 1f 89 5f 04 0f 84 fc 00 00 00 83 e8 04 0f 84 ad 00 00 00 83 e8 18 74 0b c7 07 10 00 00 c0 } //1
		$a_01_1 = {7d 04 8b f8 eb 3c b8 b6 04 01 00 89 46 70 89 46 40 89 46 38 89 46 78 c7 46 34 00 03 01 00 ff 15 } //1
		$a_00_2 = {43 3a 5c 43 6f 64 69 6e 67 5c 64 72 76 34 73 72 76 5c 6d 73 64 69 72 65 63 74 2e 70 64 62 } //1 C:\Coding\drv4srv\msdirect.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}