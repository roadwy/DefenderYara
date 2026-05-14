
rule HackTool_Win32_Patcher_AHB_MTB{
	meta:
		description = "HackTool:Win32/Patcher.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 6f 75 6e 64 20 42 69 6e 61 72 79 20 4e 69 6e 6a 61 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 70 61 74 68 3a 20 25 73 } //10 Found Binary Ninja installation path: %s
		$a_01_1 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 20 25 73 } //20 Successfully patched %s
		$a_01_2 = {42 69 6e 61 72 79 20 4e 69 6e 6a 61 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 70 61 74 68 20 6e 6f 74 20 66 6f 75 6e 64 } //30 Binary Ninja installation path not found
		$a_01_3 = {50 61 74 63 68 69 6e 67 2e 2e 2e } //40 Patching...
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}