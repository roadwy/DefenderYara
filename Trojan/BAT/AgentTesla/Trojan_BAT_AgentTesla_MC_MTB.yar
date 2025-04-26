
rule Trojan_BAT_AgentTesla_MC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 7d a2 dd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 91 00 00 00 19 00 00 00 ad } //10
		$a_01_1 = {54 72 61 63 65 4c 65 76 65 6c } //1 TraceLevel
		$a_01_2 = {4c 6f 61 64 41 75 74 6f 52 75 6e } //1 LoadAutoRun
		$a_01_3 = {6c 69 73 74 56 69 65 77 31 5f 4d 6f 75 73 65 44 6f 77 6e } //1 listView1_MouseDown
		$a_01_4 = {45 66 66 65 63 74 69 76 65 4b 65 79 53 69 7a 65 } //1 EffectiveKeySize
		$a_01_5 = {56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 57 72 69 74 65 } //1 VirtualMemoryWrite
		$a_01_6 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 KillProcess
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}
rule Trojan_BAT_AgentTesla_MC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 45 78 65 63 } //3 WinExec
		$a_81_1 = {6c 70 43 6d 64 4c 69 6e 65 } //3 lpCmdLine
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c } //3 powershell
		$a_01_3 = {27 00 44 00 6f 00 77 00 6e 00 27 00 20 00 2b 00 20 00 27 00 6c 00 6f 00 61 00 64 00 27 00 20 00 2b 00 20 00 27 00 53 00 74 00 72 00 27 00 20 00 2b 00 20 00 27 00 69 00 6e 00 67 00 27 00 } //3 'Down' + 'load' + 'Str' + 'ing'
		$a_81_4 = {74 65 73 74 2d 63 6f 6e 6e 65 63 74 69 6f 6e 20 2d 63 6f 6d 70 20 67 6f 6f 67 6c 65 2e 63 6f 6d 20 2d 63 6f 75 6e 74 20 31 20 2d 51 75 69 65 74 } //3 test-connection -comp google.com -count 1 -Quiet
		$a_81_5 = {55 73 65 72 73 5c 45 6e 67 20 4d 6f 68 61 } //3 Users\Eng Moha
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_01_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_MC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {8e 69 1e d8 6f ?? ?? ?? 0a 00 09 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 09 02 7b ?? ?? ?? 04 8e 69 1e d8 6f ?? ?? ?? 0a 00 09 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 00 09 6f ?? ?? ?? 0a 13 04 00 03 73 ?? ?? ?? 0a 13 05 00 11 05 11 04 16 73 ?? ?? ?? 0a 13 06 03 8e 69 17 da 17 d6 8d ?? ?? ?? 01 13 07 11 06 11 07 16 03 8e 69 6f ?? ?? ?? 0a 13 08 11 07 11 08 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0a de } //1
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_5 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_6 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_7 = {63 00 69 00 70 00 68 00 65 00 72 00 } //1 cipher
		$a_01_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}