
rule VirTool_Win32_VBInject_gen_AV{
	meta:
		description = "VirTool:Win32/VBInject.gen!AV,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 e9 03 00 00 68 e8 03 00 00 e8 90 01 04 8b d0 8d 4d b4 e8 90 01 04 8d 4d 98 e8 90 01 04 c7 45 fc 04 00 00 00 33 d2 8d 4d 98 e8 90 01 04 8d 45 98 50 68 ea 03 00 00 68 e8 03 00 00 e8 90 00 } //1
		$a_03_1 = {68 f5 03 00 00 68 e8 03 00 00 e8 90 01 04 8b d0 8d 8d 90 01 02 ff ff e8 90 01 04 ba 90 01 04 8d 8d 90 01 02 ff ff e8 90 01 04 ba 90 01 04 8d 8d 90 01 02 ff ff e8 90 01 04 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 e8 90 00 } //1
		$a_03_2 = {66 8b d7 66 c1 fa 0f 8b da 90 03 08 08 33 1d 90 01 04 33 55 ac 33 55 ac 33 1d 90 01 04 66 3b da 7f 39 0f bf d9 3b de 72 05 90 00 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}