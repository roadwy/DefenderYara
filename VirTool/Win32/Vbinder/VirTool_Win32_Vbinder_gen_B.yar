
rule VirTool_Win32_Vbinder_gen_B{
	meta:
		description = "VirTool:Win32/Vbinder.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d c4 fc 03 40 fc 8f e4 fc 01 00 04 e4 fc 1b 05 00 1b 06 00 0a 07 00 0c 00 04 e4 fc 5a f5 00 00 00 00 f5 04 00 00 00 04 e4 fc fe 8e 01 00 00 00 10 00 80 08 04 b8 fd 4d d4 fc 03 40 fc 8f e4 fc 00 00 04 70 fe 4d c4 fc 03 40 fc 8f e4 fc 01 00 04 8c fe 4d b4 fc 03 40 fc 8f e4 fc 02 00 fe c1 a4 fc 00 30 00 00 f5 03 00 00 00 6c e4 fc 52 fe c1 94 fc 40 00 00 00 f5 04 00 00 00 6c e4 fc 52 04 e4 fc 1b 08 00 1b 09 00 0a 07 00 0c 00 04 e4 fc 5a f5 00 00 00 00 59 90 fc 6c 90 fe f5 00 00 00 00 80 10 00 2e e8 fc 40 6c 70 fe 6c b8 fd 0a 0a 00 14 00 3c 2d e8 fc f5 00 00 00 00 04 74 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}