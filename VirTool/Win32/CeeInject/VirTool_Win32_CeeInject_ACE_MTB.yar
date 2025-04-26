
rule VirTool_Win32_CeeInject_ACE_MTB{
	meta:
		description = "VirTool:Win32/CeeInject.ACE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 94 8d fc fb ff ff 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 8b b4 bd fc fb ff ff 0f b6 d2 89 b4 8d fc fb ff ff 89 94 bd fc fb ff ff 8b b4 8d fc fb ff ff 03 f2 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 0f b6 94 b5 fc fb ff ff 8b b5 f4 fb ff ff 30 14 06 40 3b c3 } //2
		$a_01_1 = {47 8a 84 8d 04 fc ff ff 8b 94 bd fc fb ff ff 0f b6 c0 89 94 8d 04 fc ff ff 89 84 bd fc fb ff ff 33 d2 8d 46 01 f7 b5 f8 fb ff ff 0f b6 14 1a 03 94 8d 08 fc ff ff 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 8a 84 8d 08 fc ff ff 8b 94 bd fc fb ff ff 89 94 8d 08 fc ff ff 0f b6 c0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}