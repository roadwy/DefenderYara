
rule VirTool_Win32_VBInject_AFY_bit{
	meta:
		description = "VirTool:Win32/VBInject.AFY!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 01 8d 45 ?? 89 45 ?? c7 45 ?? 11 20 00 00 8d 45 ?? 50 e8 90 09 18 00 8b 45 ?? 03 85 ?? ff ff ff 0f b6 00 2b 45 ?? 8b 4d ?? 03 8d ?? ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}