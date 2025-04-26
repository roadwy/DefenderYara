
rule Trojan_Win32_Trickbot_PSB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_03_0 = {73 05 8a 4d 90 0a 0f 00 30 4c 05 ?? 40 83 f8 ?? ?? ?? ?? ?? ?? eb f1 } //10
		$a_03_1 = {41 83 f9 09 73 05 8a 90 0a 0e 00 8d 04 ?? 30 44 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb ee } //1
		$a_03_2 = {8d 04 0a 30 44 0d ?? 41 83 f9 ?? 73 05 8a 55 ?? eb ee 8d } //1
		$a_03_3 = {8d 04 0b 30 44 0d ?? 41 83 f9 ?? 73 05 8a 55 ?? eb ee 8d } //1
		$a_00_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //10 IsDebuggerPresent
		$a_00_5 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 } //10 FlushFileBuffers
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10) >=31
 
}