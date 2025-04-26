
rule Trojan_Win32_Qbot_RB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 8b 1a 03 5d a8 2b d8 4b 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 4a 8b 45 d8 33 10 89 55 a0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b ?? ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 ?? 2b 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 15 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? b8 01 00 00 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qbot_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,58 00 58 00 11 00 00 "
		
	strings :
		$a_81_0 = {63 6f 6d 65 74 2e 79 61 68 6f 6f 2e 63 6f 6d 3b 2e 68 69 72 6f 2e 74 76 3b 73 61 66 65 62 72 6f 77 73 69 6e 67 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 67 65 6f 2e 71 75 65 72 79 2e 79 61 68 6f 6f 2e 63 6f 6d 3b 67 6f 6f 67 6c 65 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f } //10 comet.yahoo.com;.hiro.tv;safebrowsing.google.com;geo.query.yahoo.com;googleusercontent.co
		$a_81_1 = {3b 73 61 6c 65 73 66 6f 72 63 65 2e 63 6f 6d 3b 6f 66 66 69 63 65 61 70 70 73 2e 6c 69 76 65 2e 63 6f 6d 3b 73 74 6f 72 61 67 65 2e 6c 69 76 65 2e 63 6f 6d 3b 6d 65 73 73 65 6e 67 65 72 2e 6c 69 76 65 2e 63 6f 6d 3b 2e 74 77 69 6d 67 2e 63 6f 6d 3b } //10 ;salesforce.com;officeapps.live.com;storage.live.com;messenger.live.com;.twimg.com;
		$a_81_2 = {61 70 69 2e 73 6b 79 70 65 2e 63 6f 6d 3b 6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 2e 62 69 6e 67 2e 63 6f 6d 3b 70 6c 61 79 74 6f 67 61 2e 63 6f 6d } //10 api.skype.com;mail.google.com;.bing.com;playtoga.com
		$a_81_3 = {73 69 74 65 61 64 76 69 73 6f 72 2e 63 6f 6d 3b 61 76 67 74 68 72 65 61 74 6c 61 62 73 2e 63 6f 6d 3b 73 61 66 65 77 65 62 2e 6e 6f 72 74 6f 6e 2e 63 6f 6d } //10 siteadvisor.com;avgthreatlabs.com;safeweb.norton.com
		$a_81_4 = {74 3d 25 73 20 74 69 6d 65 3d 5b 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 2d 25 30 32 64 2f 25 30 32 64 2f 25 64 5d } //10 t=%s time=[%02d:%02d:%02d-%02d/%02d/%d]
		$a_81_5 = {68 6f 73 74 3d 5b 25 73 3a 25 75 5d 20 75 73 65 72 3d 5b 25 73 5d 20 70 61 73 73 3d 5b 25 73 5d } //10 host=[%s:%u] user=[%s] pass=[%s]
		$a_81_6 = {75 72 6c 3d 5b 25 73 5d 20 75 73 65 72 3d 5b 25 73 5d 20 70 61 73 73 3d 5b 25 73 5d } //10 url=[%s] user=[%s] pass=[%s]
		$a_81_7 = {66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 6c 6f 67 69 6e } //10 facebook.com/login
		$a_81_8 = {61 76 63 75 66 33 32 2e 64 6c 6c } //1 avcuf32.dll
		$a_81_9 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //1 ollydbg.exe
		$a_81_10 = {77 69 6e 64 62 67 2e 65 78 65 } //1 windbg.exe
		$a_81_11 = {6e 61 76 2e 65 78 65 } //1 nav.exe
		$a_81_12 = {50 72 6f 78 69 66 69 65 72 2e 65 78 65 } //1 Proxifier.exe
		$a_81_13 = {4d 69 63 72 6f 73 6f 66 74 2e 4e 6f 74 65 73 2e 65 78 65 } //1 Microsoft.Notes.exe
		$a_81_14 = {4e 6f 72 74 6f 6e 20 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 } //1 Norton Internet Security
		$a_81_15 = {41 56 41 53 54 20 53 6f 66 74 77 61 72 65 } //1 AVAST Software
		$a_81_16 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 SELECT * FROM AntiVirusProduct
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*10+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=88
 
}