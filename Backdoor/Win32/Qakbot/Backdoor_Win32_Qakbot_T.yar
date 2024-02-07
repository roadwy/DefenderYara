
rule Backdoor_Win32_Qakbot_T{
	meta:
		description = "Backdoor:Win32/Qakbot.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 62 6f 74 5f 76 65 72 73 69 6f 6e 3d 5b 25 73 5d } //01 00  qbot_version=[%s]
		$a_01_1 = {00 75 70 64 62 6f 74 00 } //01 00  甀摰潢t
		$a_01_2 = {00 5f 71 62 6f 74 00 } //01 00 
		$a_01_3 = {25 73 5f 25 73 5f 25 75 2e 6b 63 62 } //01 00  %s_%s_%u.kcb
		$a_01_4 = {26 6e 3d 25 73 26 6f 73 3d 25 73 26 62 67 3d 25 73 26 69 74 3d 25 } //01 00  &n=%s&os=%s&bg=%s&it=%
		$a_01_5 = {20 75 73 65 72 3d 5b 25 73 5d 20 70 61 73 73 3d 5b 25 73 5d } //00 00   user=[%s] pass=[%s]
		$a_00_6 = {78 08 } //01 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Qakbot_T_2{
	meta:
		description = "Backdoor:Win32/Qakbot.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cb 83 e1 3f 8a 89 90 01 04 03 c3 30 08 75 0a 8b 4d fc 40 83 45 fc 04 89 01 43 81 fb 90 01 04 72 90 00 } //01 00 
		$a_01_1 = {25 73 61 00 6f 6b 00 00 25 73 5c 25 64 2e 65 78 65 00 00 00 2f 63 20 22 25 73 22 00 25 73 25 73 00 00 00 00 61 00 00 00 44 6e 73 63 61 63 68 65 } //01 00 
		$a_01_2 = {43 3a 00 00 53 79 73 74 65 6d 44 72 69 76 65 00 54 45 4d 50 00 } //01 00 
		$a_01_3 = {25 73 64 62 67 5f 25 73 5f 25 75 5f 71 62 6f 74 64 6c 6c 2e 74 78 74 00 71 62 6f 74 5f 64 6c 6c 5f 6d 61 69 6e } //01 00 
		$a_01_4 = {53 74 6f 70 51 62 6f 74 54 68 72 65 61 64 28 29 3a 20 77 61 69 74 69 6e 67 20 6f 6e 20 73 7a 51 62 6f 74 52 75 6e 4d 75 74 65 78 3d 27 25 73 27 } //01 00  StopQbotThread(): waiting on szQbotRunMutex='%s'
		$a_03_5 = {8b 4d fc 8d 34 08 83 e1 3f 8a 89 90 01 04 30 0e 75 0a 8b 4d f8 46 83 45 f8 04 89 31 ff 45 fc 81 7d fc 90 01 04 72 90 00 } //00 00 
		$a_00_6 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Qakbot_T_3{
	meta:
		description = "Backdoor:Win32/Qakbot.T,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 62 6f 74 5f 76 65 72 73 69 6f 6e 3d 5b 25 73 5d } //01 00  qbot_version=[%s]
		$a_01_1 = {00 75 70 64 62 6f 74 00 } //01 00  甀摰潢t
		$a_01_2 = {00 5f 71 62 6f 74 00 } //01 00 
		$a_01_3 = {25 73 5f 25 73 5f 25 75 2e 6b 63 62 } //01 00  %s_%s_%u.kcb
		$a_01_4 = {26 6e 3d 25 73 26 6f 73 3d 25 73 26 62 67 3d 25 73 26 69 74 3d 25 } //01 00  &n=%s&os=%s&bg=%s&it=%
		$a_01_5 = {20 75 73 65 72 3d 5b 25 73 5d 20 70 61 73 73 3d 5b 25 73 5d } //00 00   user=[%s] pass=[%s]
	condition:
		any of ($a_*)
 
}