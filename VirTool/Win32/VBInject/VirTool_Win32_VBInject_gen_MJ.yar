
rule VirTool_Win32_VBInject_gen_MJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!MJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {0e 6c 0c 00 43 74 ff 6c 10 00 43 70 ff 00 05 4b ff ff 00 0f 6c 70 ff 4a f5 00 00 00 00 c7 1c 25 00 00 03 14 00 02 00 0f 6c 74 ff 4a f5 } //1
		$a_01_1 = {ec fe 35 2c ff 00 1f 6c 4c ff 6c 50 ff 04 58 ff 9d e7 aa 04 ec fe fc 22 6c 44 ff fc 90 e7 aa fb } //1
		$a_01_2 = {4c ff 04 58 ff 9d fc 0d fc f0 3e ff 00 10 6c 48 ff 04 58 ff 9d 6c 4c ff 04 58 ff a2 00 0f fc e0 } //1
		$a_01_3 = {ae 04 70 ff fe 8e 01 00 11 00 01 00 80 00 f5 00 00 00 00 04 74 ff 6c 6c ff f4 01 fc cb fe 64 64 } //1
		$a_01_4 = {0b 28 ec fe 05 00 fc f6 0c ff 00 1b 28 cc fe 00 00 04 3c ff 80 10 00 f4 01 fc cb fd 69 dc fe fe } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}