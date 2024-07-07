
rule VirTool_Win32_Injector_gen_EF{
	meta:
		description = "VirTool:Win32/Injector.gen!EF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c1 88 45 fe 90 0a 2a 00 8b 4d 90 01 01 83 c1 01 90 03 05 05 81 f1 90 01 04 83 f1 90 01 01 88 8d 90 01 02 ff ff 8b 55 90 01 01 0f b6 84 15 90 01 02 ff ff 0f be 8d 90 01 02 ff ff 90 00 } //1
		$a_03_1 = {03 ca 88 4d fe 90 0a 2a 00 8b 55 90 01 01 83 c2 01 90 03 05 05 81 f2 90 01 04 83 f2 90 01 01 88 95 90 01 02 ff ff 8b 45 90 01 01 0f b6 8c 05 90 01 02 ff ff 0f be 95 90 01 02 ff ff 90 00 } //1
		$a_03_2 = {03 ca 88 4d fe 90 0a 30 00 8b 95 90 01 02 ff ff 83 c2 01 90 03 05 05 81 f2 90 01 04 83 f2 90 01 01 88 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 0f b6 8c 05 90 01 02 ff ff 0f be 95 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}