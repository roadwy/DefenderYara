
rule VirTool_Win32_VBInject_AFT{
	meta:
		description = "VirTool:Win32/VBInject.AFT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 73 8d 55 ?? 52 ff 15 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6a 6e 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 6a 78 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6a 68 8d 95 ?? ?? ff ff 52 ff 15 ?? ?? ?? ?? 6a 6b } //1
		$a_00_1 = {46 00 6c 00 61 00 77 00 6c 00 65 00 73 00 73 00 54 00 69 00 63 00 54 00 61 00 63 00 54 00 6f 00 65 00 2e 00 76 00 62 00 70 00 } //1 FlawlessTicTacToe.vbp
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}