
rule Trojan_Win32_Nuwvult_A{
	meta:
		description = "Trojan:Win32/Nuwvult.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 38 00 74 65 8b 4d fc 8b 11 52 8b 45 08 50 ff 15 90 01 04 85 c0 74 46 90 00 } //01 00 
		$a_01_1 = {4d 53 4e 54 61 73 6b 3a 3a 45 78 65 63 75 74 65 } //01 00  MSNTask::Execute
		$a_01_2 = {53 74 61 72 74 50 61 67 65 54 61 73 6b 3a 3a 45 78 65 63 75 74 65 } //01 00  StartPageTask::Execute
		$a_01_3 = {41 64 54 61 73 6b 3a 3a 44 6f 77 6e 6c 6f 61 64 54 61 73 6b 73 } //01 00  AdTask::DownloadTasks
		$a_01_4 = {76 00 65 00 72 00 3d 00 79 00 6f 00 75 00 74 00 75 00 62 00 65 00 } //01 00  ver=youtube
		$a_01_5 = {2a 00 53 00 6b 00 79 00 70 00 65 00 2a 00 20 00 63 00 6f 00 6e 00 76 00 65 00 72 00 73 00 61 00 } //00 00  *Skype* conversa
	condition:
		any of ($a_*)
 
}