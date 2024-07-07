
rule HackTool_Win32_IRCFlood_A{
	meta:
		description = "HackTool:Win32/IRCFlood.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 66 6c 6f 6f 64 5f 73 74 61 72 74 00 } //1
		$a_00_1 = {46 00 6c 00 6f 00 6f 00 64 00 54 00 79 00 70 00 65 00 3d 00 } //1 FloodType=
		$a_80_2 = {49 63 71 20 46 6c 6f 6f 64 65 72 20 62 79 20 6b 61 72 61 73 20 56 } //Icq Flooder by karas V  1
		$a_00_3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 2c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 44 00 4c 00 4c 00 20 00 64 00 65 00 73 00 6b 00 2e 00 63 00 70 00 6c 00 2c 00 2c 00 30 00 } //1 rundll32.exe shell32.dll,Control_RunDLL desk.cpl,,0
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}