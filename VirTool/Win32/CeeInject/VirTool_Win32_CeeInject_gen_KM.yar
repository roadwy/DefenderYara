
rule VirTool_Win32_CeeInject_gen_KM{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 83 bd 90 01 02 ff ff 32 7c 90 01 01 8b 85 90 01 02 ff ff 83 c0 01 89 85 90 1b 02 ff ff 8b 8d 90 1b 02 ff ff 83 c1 01 83 f1 90 01 01 88 8d 90 01 02 ff ff 8b 95 90 1b 02 ff ff 0f be 84 15 90 01 02 ff ff 0f be 8d 90 01 02 ff ff 03 c1 88 85 90 01 02 ff ff 90 00 } //1
		$a_03_1 = {83 c4 08 83 bd 90 01 02 ff ff 32 7c 90 01 01 8b 90 03 01 01 4d 55 90 01 01 83 90 03 01 01 c1 c2 01 89 90 03 01 01 4d 55 90 1b 03 8b 90 03 01 01 45 55 90 1b 03 83 90 03 01 01 c0 c2 01 90 03 07 0a 35 90 01 01 00 00 00 83 90 03 01 01 f0 f2 90 01 01 88 90 03 01 01 85 95 90 01 02 ff ff 8b 90 03 01 01 45 4d 90 1b 03 0f be 90 03 02 02 8c 05 94 0d 90 01 02 ff ff 0f be 90 03 01 01 85 95 90 01 02 ff ff 03 90 03 01 01 ca d0 88 90 03 01 01 4d 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}