
rule VirTool_WinNT_Ghodow_B{
	meta:
		description = "VirTool:WinNT/Ghodow.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 00 00 ff bf d1 e0 0f b6 88 d4 02 00 00 01 0d } //1
		$a_01_1 = {81 39 1d 00 00 c0 75 15 90 8b 4d 10 8b 91 b8 00 00 00 83 c2 02 89 91 b8 00 00 00 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}