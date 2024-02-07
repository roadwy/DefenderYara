
rule Trojan_BAT_AgentTesla_BH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 59 00 00 00 0e 00 00 00 14 00 00 00 } //01 00 
		$a_01_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 49 00 4d 00 20 00 73 00 79 00 73 00 6b 00 65 00 79 00 2e 00 65 00 78 00 65 00 20 00 3e 00 6e 00 75 00 6c 00 } //01 00  taskkill /f /IM syskey.exe >nul
		$a_01_2 = {73 76 63 68 6f 73 74 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  svchost.Form1.resources
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}