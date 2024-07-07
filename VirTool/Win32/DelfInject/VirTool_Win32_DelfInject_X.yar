
rule VirTool_Win32_DelfInject_X{
	meta:
		description = "VirTool:Win32/DelfInject.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 85 6c fe ff ff 50 ff d7 46 4b 75 a0 } //1
		$a_01_1 = {81 bd a4 fe ff ff 50 45 00 00 0f 85 } //1
		$a_00_2 = {bf cc cc cc 0c 8a 1e 46 80 fb 20 74 f8 b5 00 80 fb 2d 74 62 80 fb 2b 74 5f 80 fb 24 74 5f 80 fb 78 74 5a 80 fb 58 74 55 80 fb 30 75 13 8a 1e 46 80 fb 78 74 48 80 fb 58 74 43 84 db 74 20 eb 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}