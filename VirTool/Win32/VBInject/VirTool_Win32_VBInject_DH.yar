
rule VirTool_Win32_VBInject_DH{
	meta:
		description = "VirTool:Win32/VBInject.DH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 16 00 00 00 8d 45 d8 50 8d 45 dc 50 e8 90 01 02 ff ff c7 45 fc 17 00 00 00 8d 45 d8 50 8d 45 dc 50 e8 90 01 02 ff ff c7 45 fc 18 00 00 00 c7 90 02 05 e8 03 00 00 c7 90 02 05 01 00 00 00 c7 90 02 05 01 00 00 00 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}