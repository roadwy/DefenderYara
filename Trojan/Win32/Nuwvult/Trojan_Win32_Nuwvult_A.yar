
rule Trojan_Win32_Nuwvult_A{
	meta:
		description = "Trojan:Win32/Nuwvult.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 38 00 74 65 8b 4d fc 8b 11 52 8b 45 08 50 ff 15 ?? ?? ?? ?? 85 c0 74 46 } //3
		$a_01_1 = {4d 53 4e 54 61 73 6b 3a 3a 45 78 65 63 75 74 65 } //1 MSNTask::Execute
		$a_01_2 = {53 74 61 72 74 50 61 67 65 54 61 73 6b 3a 3a 45 78 65 63 75 74 65 } //1 StartPageTask::Execute
		$a_01_3 = {41 64 54 61 73 6b 3a 3a 44 6f 77 6e 6c 6f 61 64 54 61 73 6b 73 } //1 AdTask::DownloadTasks
		$a_01_4 = {76 00 65 00 72 00 3d 00 79 00 6f 00 75 00 74 00 75 00 62 00 65 00 } //1 ver=youtube
		$a_01_5 = {2a 00 53 00 6b 00 79 00 70 00 65 00 2a 00 20 00 63 00 6f 00 6e 00 76 00 65 00 72 00 73 00 61 00 } //1 *Skype* conversa
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}