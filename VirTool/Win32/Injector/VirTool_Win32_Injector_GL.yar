
rule VirTool_Win32_Injector_GL{
	meta:
		description = "VirTool:Win32/Injector.GL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 08 8b 45 ?? 99 f7 7d ?? 89 d0 89 c2 8b 45 10 01 d0 0f b6 00 31 c8 8d 8d ?? ?? ff ff 8b 55 ?? 01 ca 88 02 83 45 ?? 01 8b 45 ?? 99 f7 7d ?? 89 d0 85 c0 75 07 c7 45 ?? 00 00 00 00 83 45 ?? 01 8b 45 ?? 3b 45 ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}