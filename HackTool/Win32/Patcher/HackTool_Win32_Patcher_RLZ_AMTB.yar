
rule HackTool_Win32_Patcher_RLZ_AMTB{
	meta:
		description = "HackTool:Win32/Patcher.RLZ!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 5d f8 8a 5c 0b ff 3a 18 74 07 e8 e3 c3 ff ff eb 2e 41 40 4a 75 e9 } //6
		$a_80_1 = {52 4c 7a 65 72 20 50 61 74 63 68 65 72 } //RLzer Patcher  1
	condition:
		((#a_01_0  & 1)*6+(#a_80_1  & 1)*1) >=7
 
}