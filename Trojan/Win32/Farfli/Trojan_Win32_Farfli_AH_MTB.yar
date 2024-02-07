
rule Trojan_Win32_Farfli_AH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {4d 46 43 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 41 70 70 49 44 2e 4e 6f 56 65 72 73 69 6f 6e } //03 00  MFCApplication1.AppID.NoVersion
		$a_01_1 = {66 75 63 6b 79 6f 75 } //03 00  fuckyou
		$a_01_2 = {55 73 65 72 73 5c 4d 52 4b } //03 00  Users\MRK
		$a_01_3 = {38 30 38 38 77 77 63 32 32 30 33 31 38 76 73 32 30 32 32 4d 46 43 } //03 00  8088wwc220318vs2022MFC
		$a_01_4 = {4d 46 43 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //03 00  MFCApplication1.pdb
		$a_01_5 = {53 6c 65 65 70 43 6f 6e 64 69 74 69 6f 6e 56 61 72 69 61 62 6c 65 43 53 } //00 00  SleepConditionVariableCS
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 f4 83 c0 01 89 45 f4 83 7d f4 06 73 1e 8b 4d fc 6b c9 30 8b 55 f4 8b 45 f4 66 8b 8c 41 bc b1 5b 00 66 89 0c 55 50 5c 5c 00 eb d3 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 65 69 78 69 6e 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 77 65 69 78 69 6e } //01 00  http://weixin.sogou.com/weixin
		$a_01_2 = {68 74 74 70 3a 2f 2f 7a 68 69 68 75 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 7a 68 69 68 75 } //01 00  http://zhihu.sogou.com/zhihu
		$a_01_3 = {68 74 74 70 3a 2f 2f 6d 69 6e 67 79 69 2e 73 6f 67 6f 75 2e 63 6f 6d 2f 6d 69 6e 67 79 69 } //01 00  http://mingyi.sogou.com/mingyi
		$a_01_4 = {65 6e 63 6f 64 65 55 52 49 43 6f 6d 70 6f 6e 65 6e 74 } //01 00  encodeURIComponent
		$a_01_5 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00  UnhookWindowsHookEx
	condition:
		any of ($a_*)
 
}