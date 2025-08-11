
rule VirTool_Win32_Defnot_B{
	meta:
		description = "VirTool:Win32/Defnot.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 56 ff ?? ?? ?? ?? ?? 8b c8 83 f9 ff 89 0f 0f 95 c0 88 47 04 ?? ?? 6a 02 6a 00 6a 00 56 51 ff } //10
		$a_01_1 = {8b 45 20 0b 45 24 6a 00 50 ff 75 18 ff 75 0c ff 75 1c ff 75 14 ff 75 08 ff } //1
		$a_01_2 = {64 65 66 65 6e 64 65 72 2d 64 69 73 61 62 6c 65 72 2d 69 70 63 } //1 defender-disabler-ipc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}