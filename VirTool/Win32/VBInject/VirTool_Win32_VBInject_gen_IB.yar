
rule VirTool_Win32_VBInject_gen_IB{
	meta:
		description = "VirTool:Win32/VBInject.gen!IB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 c1 06 50 6a 02 0f 80 90 01 04 51 56 ff 52 90 01 01 8b 85 90 01 02 ff ff 83 e8 01 0f 80 90 01 04 33 c9 89 85 90 01 02 ff ff 89 4d b4 3b c8 0f 8f 90 01 04 81 c3 f8 00 00 00 ba 90 01 04 0f 80 90 01 04 6b c9 28 90 00 } //2
		$a_03_1 = {66 0f b6 0c 08 8b 95 90 01 02 ff ff 8b 45 90 01 01 66 33 0c 50 90 00 } //2
		$a_00_2 = {65 00 64 00 61 00 7a 00 2e 00 76 00 62 00 70 00 } //1 edaz.vbp
		$a_00_3 = {73 00 63 00 52 00 56 00 31 00 75 00 4b 00 61 00 4f 00 } //1 scRV1uKaO
		$a_03_4 = {ff ff 50 45 00 00 0f 85 90 09 04 00 81 bd 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}