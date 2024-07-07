
rule VirTool_Win32_CeeInject_gen_KD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8a 55 e3 88 95 90 01 01 f0 ff ff 8b 45 90 01 01 8a 8d 90 1b 00 f0 ff ff 88 88 90 01 04 eb 90 01 01 8b 95 90 01 01 f0 ff ff 81 c2 90 01 04 ff d2 90 00 } //1
		$a_03_1 = {83 c4 04 8a 4d e3 88 8d 90 01 01 f0 ff ff 8b 55 90 01 01 8a 85 90 1b 00 f0 ff ff 88 82 90 01 04 eb 90 01 01 8b 8d 90 01 01 f0 ff ff 81 c1 90 01 04 ff d1 90 00 } //1
		$a_03_2 = {83 c4 04 89 85 90 01 02 ff ff 8a 85 90 01 02 ff ff 88 85 90 01 02 ff ff 8b 8d 90 01 02 ff ff 8a 95 90 01 02 ff ff 88 94 0d 90 01 02 ff ff e9 90 01 01 ff ff ff 8b 85 90 01 02 ff ff 8d 8c 05 90 1b 05 ff ff ff d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}