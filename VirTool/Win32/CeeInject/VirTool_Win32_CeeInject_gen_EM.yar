
rule VirTool_Win32_CeeInject_gen_EM{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 51 06 39 95 90 01 02 ff ff 7d 90 01 01 8b 85 90 01 02 ff ff 8b 48 3c 8b 55 90 01 01 8d 84 0a f8 00 00 00 8b 8d 90 01 02 ff ff 6b c9 28 03 c1 90 00 } //1
		$a_03_1 = {6a 00 6a 04 8d 90 04 01 06 45 5d 4d 55 75 7d 90 01 01 90 04 01 06 50 53 51 52 56 57 8b 90 04 01 06 85 9d 8d 95 b5 bd 90 01 02 ff ff 83 90 04 01 06 c0 c3 c1 c2 c6 c7 08 90 04 01 06 50 53 51 52 56 57 8b 90 04 01 06 45 5d 4d 55 75 7d 90 01 01 90 04 01 06 50 53 51 52 56 57 ff 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}