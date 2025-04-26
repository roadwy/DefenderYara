
rule VirTool_WinNT_Siapag_gen_A{
	meta:
		description = "VirTool:WinNT/Siapag.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {56 57 60 b8 ?? 00 00 00 bb ?? 00 00 00 90 90 90 90 90 90 61 } //10
		$a_00_1 = {8b 45 e0 8b 30 a1 90 08 01 00 39 70 08 77 09 c7 45 e4 0d 00 00 c0 eb } //10
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 52 00 45 00 53 00 53 00 44 00 54 00 } //1 \Device\RESSDT
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=11
 
}