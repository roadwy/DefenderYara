
rule VirTool_Win32_Hercules_G_MTB{
	meta:
		description = "VirTool:Win32/Hercules.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 79 73 63 61 6c 6c 2e 63 6f 6e 6e 65 63 74 } //2 syscall.connect
		$a_00_1 = {45 47 45 53 50 4c 4f 49 54 } //2 EGESPLOIT
		$a_00_2 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 20 6f 6e 6c 79 20 62 65 20 72 75 6e 20 6f 6e 20 70 72 6f 63 65 73 73 6f 72 73 20 77 69 74 68 20 4d 4d 58 20 73 75 70 70 6f 72 74 } //2 This program can only be run on processors with MMX support
		$a_02_3 = {84 00 8b 05 68 ?? ?? 00 90 90 8b 0d ?? ?? ?? 00 90 90 89 04 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 89 4c 24 0c 8b 44 24 2c 89 44 24 10 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 e8 73 05 00 00 8b 44 24 1c 85 c0 74 16 8b 0d } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=8
 
}