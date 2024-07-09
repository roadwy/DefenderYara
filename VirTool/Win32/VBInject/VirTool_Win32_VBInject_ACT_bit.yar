
rule VirTool_Win32_VBInject_ACT_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACT!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ad 83 f8 00 74 fa bb 56 8b ec 83 4b 39 18 75 f0 81 78 04 ec 0c 56 8d 75 e7 31 db 53 53 53 54 68 ?? ?? ?? ?? 52 51 54 89 85 c0 00 00 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}