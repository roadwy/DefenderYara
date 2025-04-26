
rule VirTool_Win32_VBInject_RA{
	meta:
		description = "VirTool:Win32/VBInject.RA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 51 53 ff 52 2c 3b c6 db e2 7d } //1
		$a_02_1 = {42 00 6f 00 74 00 65 00 6c 00 6c 00 5c 00 [0-40] 42 00 6f 00 74 00 [0-20] 2e 00 76 00 62 00 70 00 } //1
		$a_00_2 = {42 00 6f 00 74 00 65 00 6c 00 6c 00 61 00 42 00 6f 00 20 00 74 00 65 00 6c 00 6c 00 2e 00 73 00 63 00 72 00 } //1 BotellaBo tell.scr
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}