
rule Trojan_Win32_AgentTesla_CD_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0e 84 c9 74 09 88 0a 42 46 ff 4d 0c 75 f1 } //01 00 
		$a_03_1 = {0f b6 cb 8d 54 85 a4 d3 2a 33 d2 42 8b cf d3 e2 40 4f 3b c6 89 94 85 90 02 04 76 e3 90 00 } //01 00 
		$a_01_2 = {73 74 61 72 74 20 52 69 63 6f 6e 6f 62 62 65 2e 65 78 65 2e 63 6f 6d } //01 00  start Riconobbe.exe.com
		$a_01_3 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //01 00  DecryptFileA
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //00 00  Software\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		any of ($a_*)
 
}