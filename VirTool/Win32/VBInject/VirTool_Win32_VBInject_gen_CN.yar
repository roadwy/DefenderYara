
rule VirTool_Win32_VBInject_gen_CN{
	meta:
		description = "VirTool:Win32/VBInject.gen!CN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_03_0 = {6c b0 fe 6c a4 fe aa [0-0d] 71 8c fd } //3
		$a_03_1 = {6c b0 fe fd 69 ?? fc [0-10] 6c a4 fe fd 69 ?? fc [0-28] 71 8c fd } //3
		$a_01_2 = {6c 78 fe 6c 6c fe aa 71 90 fd } //3
		$a_03_3 = {6c 78 fe fd 69 [0-10] 6c 6c fe fd 69 [0-20] 71 ec fd } //3
		$a_01_4 = {6c 44 ff 94 08 00 fc 01 aa 99 08 00 98 01 1b } //3
		$a_01_5 = {6c ec fc 6c 68 fe aa 71 a0 fd } //3
		$a_03_6 = {f3 c3 00 fc 0d [0-09] f3 cc 00 fc 0d } //1
		$a_01_7 = {f5 04 00 00 00 f5 58 59 59 59 } //1
		$a_03_8 = {f4 58 fc 0d [0-11] f4 59 fc 0d [0-11] f4 59 fc 0d [0-11] f4 59 fc 0d } //1
		$a_03_9 = {ff f5 f8 00 00 00 aa f5 28 00 00 00 6c ?? ff b2 aa f5 90 04 01 02 0c 14 00 00 00 aa 90 09 02 00 6c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*3+(#a_03_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*2) >=4
 
}