
rule VirTool_WinNT_Koobface_gen_B{
	meta:
		description = "VirTool:WinNT/Koobface.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 61 6e 66 63 } //1 hanfc
		$a_01_1 = {68 61 6e 66 72 } //1 hanfr
		$a_01_2 = {81 fb 7f 00 00 01 74 2c 85 db 74 28 39 59 24 74 23 } //2
		$a_01_3 = {81 e9 9c 01 22 00 74 12 83 e9 08 75 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}