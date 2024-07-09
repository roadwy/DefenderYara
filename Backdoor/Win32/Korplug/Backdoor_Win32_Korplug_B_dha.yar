
rule Backdoor_Win32_Korplug_B_dha{
	meta:
		description = "Backdoor:Win32/Korplug.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 f2 ae f7 d1 49 51 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 33 c0 b9 19 00 00 00 8d 7c ?? ?? 50 50 50 50 f3 ab 68 ?? ?? ?? ?? c7 44 ?? ?? 00 00 00 00 ff 15 } //3
		$a_00_1 = {63 6d 64 20 2f 63 20 22 70 69 6e 67 20 31 26 64 65 6c 20 2f 51 20 22 25 73 2a 2e 2a } //1 cmd /c "ping 1&del /Q "%s*.*
		$a_00_2 = {73 6c 69 64 65 73 2e 69 6e 66 } //1 slides.inf
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=5
 
}