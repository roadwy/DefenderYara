
rule VirTool_Win32_VBInject_YZ{
	meta:
		description = "VirTool:Win32/VBInject.YZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 c1 84 c0 74 07 c7 44 c1 04 c1 cf 0d 03 e9 ?? ?? 00 00 c7 85 1c ff ff ff 6e 00 00 00 81 bd 1c ff ff ff a1 00 00 00 73 ?? 83 a5 f0 fe ff ff 00 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}