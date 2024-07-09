
rule VirTool_Win32_VBInject_ADF_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADF!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c3 5e 8b 7c 24 10 b9 00 20 00 00 90 09 07 00 81 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 57 f3 66 a5 5f b8 04 00 00 00 d9 d0 e8 dd ff ff ff d9 d0 01 c1 81 f9 00 20 00 00 75 ed ff e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}