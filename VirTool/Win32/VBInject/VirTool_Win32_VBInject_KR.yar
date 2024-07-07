
rule VirTool_Win32_VBInject_KR{
	meta:
		description = "VirTool:Win32/VBInject.KR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 51 0c 8b 8d 90 01 02 ff ff 88 04 0a 90 03 01 01 e9 eb 90 0a 50 00 8b 90 01 01 0c 8b 90 01 03 ff ff 33 90 01 01 8a 90 01 02 90 02 10 33 0c 90 03 02 01 90 90 82 ff 15 90 01 01 10 40 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}