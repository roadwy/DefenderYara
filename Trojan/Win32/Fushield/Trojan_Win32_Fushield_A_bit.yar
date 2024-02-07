
rule Trojan_Win32_Fushield_A_bit{
	meta:
		description = "Trojan:Win32/Fushield.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 04 00 "
		
	strings :
		$a_03_0 = {88 54 35 c8 46 3b f7 7c 90 09 0b 00 e8 90 01 04 99 f7 fb 80 c2 61 90 00 } //04 00 
		$a_00_1 = {2e 74 65 6d 70 2e 66 6f 72 74 65 73 74 } //03 00  .temp.fortest
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {45 6e 61 62 6c 65 4c 55 41 } //01 00  EnableLUA
		$a_00_4 = {50 72 6f 6d 70 74 4f 6e 53 65 63 75 72 65 44 65 73 6b 74 6f 70 } //01 00  PromptOnSecureDesktop
		$a_00_5 = {55 41 43 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //0a 00  UACDisableNotify
		$a_00_6 = {46 75 63 6b 53 68 69 65 6c 64 52 65 66 72 65 73 68 4d 75 74 65 78 } //00 00  FuckShieldRefreshMutex
		$a_00_7 = {5d 04 00 00 32 7b 03 80 5c 27 00 00 } //33 7b 
	condition:
		any of ($a_*)
 
}