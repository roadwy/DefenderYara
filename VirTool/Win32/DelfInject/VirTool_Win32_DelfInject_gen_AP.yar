
rule VirTool_Win32_DelfInject_gen_AP{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AP,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 9d bb ca aa bf b9 c1 99 c5 cb c4 ca 00 00 } //5
		$a_01_1 = {00 a9 c2 bb bb c6 00 00 } //5
		$a_01_2 = {00 af c1 d0 b0 c4 ce c1 bd c0 9f cb ca d0 c1 d4 d0 00 00 } //5
		$a_01_3 = {0f 31 8b c8 0f 31 2b c8 f7 d1 81 f9 00 00 01 00 7f } //5
		$a_01_4 = {00 00 89 45 e4 c7 45 f0 01 00 00 00 8b 45 fc 8b 55 f0 0f b6 44 10 ff 89 45 ec } //5
		$a_01_5 = {8d 45 e8 8a 55 ec 80 ea } //5
		$a_03_6 = {ff ff 8b 45 f8 ff 30 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 75 e8 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8b 45 f8 ba 0e 00 00 00 e8 90 01 03 ff 8b 45 f8 ff 30 6a 00 6a 00 6a 00 6a 00 6a 00 8b 45 f8 ba 06 00 90 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_03_6  & 1)*5) >=15
 
}