
rule Backdoor_Win32_PcClient_CM{
	meta:
		description = "Backdoor:Win32/PcClient.CM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3b d3 76 2e bf 90 01 04 81 3c 01 90 01 04 75 06 39 7c 01 04 74 07 41 3b ca 72 ec eb 13 90 00 } //01 00 
		$a_01_1 = {2b f0 8a 14 06 8a 18 3a d3 75 11 41 40 3b cf 7c f1 } //01 00 
		$a_03_2 = {76 12 80 3c 38 0d 74 13 47 8b cb 2b cf 83 e9 90 01 01 3b f9 72 ee 47 3b fb 72 ac eb 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_PcClient_CM_2{
	meta:
		description = "Backdoor:Win32/PcClient.CM,SIGNATURE_TYPE_PEHSTR,1c 00 14 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {31 30 31 39 38 3d 70 6f 6c 6d 78 68 61 74 } //0a 00  10198=polmxhat
		$a_01_1 = {31 30 32 36 32 3d 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 25 73 20 53 65 72 76 65 72 41 64 64 72 3d 25 73 3b 53 65 72 76 65 72 50 6f 72 74 3d 25 64 3b 48 77 6e 64 3d 25 64 3b 43 6d 64 3d 25 64 3b 44 64 6e 73 55 72 6c 3d 25 73 3b } //05 00  10262=rundll32.exe "%s",%s ServerAddr=%s;ServerPort=%d;Hwnd=%d;Cmd=%d;DdnsUrl=%s;
		$a_01_2 = {6a 69 65 62 69 61 6f 2e 33 33 32 32 2e 6f 72 67 } //01 00  jiebiao.3322.org
		$a_01_3 = {31 30 32 38 31 3d 5c 25 73 73 63 6b 2e 69 6e 69 } //01 00  10281=\%ssck.ini
		$a_01_4 = {31 30 33 31 31 3d 5c 25 73 63 74 72 2e 64 6c 6c } //01 00  10311=\%sctr.dll
		$a_01_5 = {31 30 32 38 32 3d 5c 25 73 6b 65 79 2e 64 6c 6c } //01 00  10282=\%skey.dll
		$a_01_6 = {31 30 32 38 33 3d 5c 25 73 6b 65 79 2e 74 78 74 } //01 00  10283=\%skey.txt
		$a_01_7 = {31 30 33 31 32 3d 5c 25 73 74 6d 70 2e 65 78 65 } //01 00  10312=\%stmp.exe
		$a_01_8 = {31 30 32 34 30 3d 25 73 72 65 67 2e 64 6c 6c } //01 00  10240=%sreg.dll
		$a_01_9 = {31 30 32 33 39 3d 25 73 72 65 67 2e 72 65 67 } //01 00  10239=%sreg.reg
		$a_01_10 = {31 30 32 30 32 3d 25 73 63 6f 6d 2e 65 78 65 } //00 00  10202=%scom.exe
	condition:
		any of ($a_*)
 
}