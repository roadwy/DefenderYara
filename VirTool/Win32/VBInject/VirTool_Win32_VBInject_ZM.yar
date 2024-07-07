
rule VirTool_Win32_VBInject_ZM{
	meta:
		description = "VirTool:Win32/VBInject.ZM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 85 50 f7 ff ff cf 00 90 00 89 bd 48 f7 ff ff 8d 95 48 f7 ff ff 8b 45 a8 b9 85 00 00 00 2b 48 14 c1 e1 04 03 48 0c ff d6 8b 45 a8 b9 86 00 00 00 c7 85 40 f7 ff ff 0d 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}