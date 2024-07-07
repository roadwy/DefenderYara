
rule VirTool_Win32_VBInject_gen_EJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!EJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 08 8b 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 66 33 0c 50 ff 15 90 00 } //1
		$a_03_1 = {68 f8 00 00 00 e8 90 01 04 ff 15 90 01 04 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 81 bd 90 01 02 ff ff 50 45 00 00 0f 85 90 00 } //1
		$a_03_2 = {05 f8 00 00 00 0f 80 90 01 02 00 00 6b d2 28 0f 80 90 01 02 00 00 03 c2 8b 51 14 0f 80 90 01 02 00 00 2b c2 8b 51 10 3b c2 89 85 90 01 02 ff ff 72 20 90 00 } //1
		$a_02_3 = {81 c1 84 01 00 00 ff d6 8b 85 48 ff ff ff ba e8 90 01 01 40 00 8d 88 88 01 00 00 ff d6 8b 8d 48 ff ff ff ba e8 90 01 01 40 00 81 c1 8c 01 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}