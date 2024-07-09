
rule VirTool_Win32_CeeInject_gen_KM{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 83 bd ?? ?? ff ff 32 7c ?? 8b 85 ?? ?? ff ff 83 c0 01 89 85 90 1b 02 ff ff 8b 8d 90 1b 02 ff ff 83 c1 01 83 f1 ?? 88 8d ?? ?? ff ff 8b 95 90 1b 02 ff ff 0f be 84 15 ?? ?? ff ff 0f be 8d ?? ?? ff ff 03 c1 88 85 ?? ?? ff ff } //1
		$a_03_1 = {83 c4 08 83 bd ?? ?? ff ff 32 7c ?? 8b (4d|55) ?? 83 (|) c1 c2 01 89 (4d|55) 90 1b 03 8b (|) 45 55 90 1b 03 83 (|) c0 c2 01 90 03 07 0a 35 ?? 00 00 00 83 (|) f0 f2 ?? 88 (|) 85 95 ?? ?? ff ff 8b (|) 45 4d 90 1b 03 0f be 90 03 02 02 8c 05 94 0d ?? ?? ff ff 0f be (|) 85 95 ?? ?? ff ff 03 (|) ca d0 88 (4d|55) } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}