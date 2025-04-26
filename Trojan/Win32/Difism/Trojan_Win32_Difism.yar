
rule Trojan_Win32_Difism{
	meta:
		description = "Trojan:Win32/Difism,SIGNATURE_TYPE_PEHSTR,0a 00 08 00 11 00 00 "
		
	strings :
		$a_01_0 = {a5 a5 a5 6a 10 59 a5 6a 01 89 85 } //1
		$a_01_1 = {a5 a5 a5 a5 66 a5 33 f6 83 7b 28 01 0f 85 } //1
		$a_01_2 = {0f b6 08 8a 4c 31 08 30 0a 42 fe 00 4f 75 f1 } //1
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 47 49 41 4e 54 43 6f 6d 70 61 6e 79 5c 41 6e 74 69 53 70 79 77 61 72 65 } //1 Software\GIANTCompany\AntiSpyware
		$a_01_4 = {4d 6f 6e 69 74 6f 72 5f 49 45 50 6c 75 67 69 6e 73 5f 45 6e 61 62 6c 65 64 } //2 Monitor_IEPlugins_Enabled
		$a_01_5 = {46 69 72 65 77 61 6c 6c 5c 4d 70 66 55 69 2e 44 6c 6c } //1 Firewall\MpfUi.Dll
		$a_01_6 = {50 72 6f 5c 53 6e 6f 72 74 49 6d 70 2e 64 6c 6c } //1 Pro\SnortImp.dll
		$a_01_7 = {46 69 72 65 77 61 6c 6c 5c 45 6e 67 69 6e 65 2e 64 6c 6c } //1 Firewall\Engine.dll
		$a_01_8 = {5a 6f 6e 65 41 6c 61 72 6d 5c 76 73 72 75 6c 65 64 62 2e 64 6c 6c } //1 ZoneAlarm\vsruledb.dll
		$a_01_9 = {46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //2 FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_10 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 } //2 CONNECT %s:%d HTTP
		$a_01_11 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //2 :*:Enabled:
		$a_01_12 = {2f 74 61 6b 65 6d 65 32 2f 3f 61 3d } //2 /takeme2/?a=
		$a_01_13 = {73 6f 75 6e 64 00 00 00 6d 70 33 7a } //2
		$a_01_14 = {64 62 78 00 6d 73 67 00 70 70 74 00 6e 66 6f } //2
		$a_01_15 = {2e 62 69 7a 00 68 74 74 70 3a 2f 2f } //2 戮穩栀瑴㩰⼯
		$a_01_16 = {61 62 6f 75 74 3a 62 6c 61 6e 6b } //1 about:blank
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2+(#a_01_14  & 1)*2+(#a_01_15  & 1)*2+(#a_01_16  & 1)*1) >=8
 
}