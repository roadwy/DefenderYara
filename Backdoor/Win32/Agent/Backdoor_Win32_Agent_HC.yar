
rule Backdoor_Win32_Agent_HC{
	meta:
		description = "Backdoor:Win32/Agent.HC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {80 30 26 40 3d ?? ?? ?? ?? 72 f5 e9 } //2
		$a_00_1 = {33 d2 f7 75 0c 8b 45 08 85 d2 74 0a } //1
		$a_00_2 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}