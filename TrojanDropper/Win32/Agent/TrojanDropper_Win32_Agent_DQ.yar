
rule TrojanDropper_Win32_Agent_DQ{
	meta:
		description = "TrojanDropper:Win32/Agent.DQ,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 4d 6f 6e 20 61 64 64 65 64 20 74 6f 20 72 65 67 2e } //1 SysMon added to reg.
		$a_01_1 = {2d 78 73 79 73 6d 6f 6e } //1 -xsysmon
		$a_01_2 = {55 70 64 4d 6f 6e 20 61 64 64 65 64 20 74 6f 20 72 65 67 2e } //1 UpdMon added to reg.
		$a_01_3 = {2d 78 75 70 64 6d 6f 6e } //1 -xupdmon
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 Software\Microsoft\Windows\CurrentVersion\Run
		$a_03_5 = {40 55 50 ff 15 ?? ?? 40 00 83 c4 08 85 c0 75 ?? 8b 44 24 24 50 6a 01 68 01 00 10 00 ff 15 ?? ?? 40 00 8b 8c 24 4c 01 00 00 8b 54 24 24 8b f8 89 11 eb 04 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*5+(#a_03_5  & 1)*5) >=12
 
}