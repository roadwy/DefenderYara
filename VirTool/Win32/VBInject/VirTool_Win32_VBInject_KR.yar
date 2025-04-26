
rule VirTool_Win32_VBInject_KR{
	meta:
		description = "VirTool:Win32/VBInject.KR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 51 0c 8b 8d ?? ?? ff ff 88 04 0a (e9|eb) 90 0a 50 00 8b ?? 0c 8b ?? ?? ?? ff ff 33 ?? 8a ?? ?? [0-10] 33 0c 90 03 02 01 90 90 82 ff 15 ?? 10 40 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}