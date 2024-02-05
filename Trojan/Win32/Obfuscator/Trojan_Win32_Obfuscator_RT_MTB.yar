
rule Trojan_Win32_Obfuscator_RT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 33 05 90 01 04 c7 05 90 01 04 00 00 00 00 8b d0 01 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 8b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Obfuscator_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 c0 bb 03 00 a3 90 01 04 c7 45 90 01 01 00 00 00 00 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 03 55 90 01 01 3b ca 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Obfuscator_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Obfuscator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 08 81 f1 80 00 00 00 88 90 01 02 8b 90 01 02 03 90 01 02 89 55 90 01 01 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 4d 90 01 01 0f b6 11 0f b6 45 90 01 01 33 d0 8b 4d 90 01 01 2b 4d 90 01 01 0f b6 c1 25 80 00 00 00 33 d0 8b 4d 90 01 01 88 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Obfuscator_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Obfuscator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {72 63 70 2d 62 65 2d 73 61 6e 69 74 69 7a 65 72 } //rcp-be-sanitizer  01 00 
		$a_80_1 = {2d 2d 6c 6f 67 69 6e 2e 73 65 73 73 69 6f 6e 4b 65 79 } //--login.sessionKey  01 00 
		$a_80_2 = {72 73 6f 2d 61 75 74 68 2e 75 73 65 72 6e 61 6d 65 } //rso-auth.username  01 00 
		$a_80_3 = {72 73 6f 2d 61 75 74 68 2e 70 61 73 73 77 6f 72 64 } //rso-auth.password  01 00 
		$a_80_4 = {6e 65 77 5f 67 61 6d 65 5f 70 61 74 63 68 65 72 } //new_game_patcher  01 00 
		$a_80_5 = {61 6c 6c 6f 77 5f 69 6e 73 65 63 75 72 65 5f 63 6f 6e 74 65 6e 74 } //allow_insecure_content  01 00 
		$a_80_6 = {54 3a 5c 63 69 64 5c 70 34 5c 52 65 6c 65 61 73 65 73 5f 31 31 5f 32 34 5c 4c 65 61 67 75 65 43 6c 69 65 6e 74 43 6f 64 65 5f 58 38 36 5f 50 75 62 6c 69 63 5c 31 35 36 38 32 5c 74 6d 70 5c 78 38 36 2d 50 75 62 6c 69 63 2d 4c 43 55 5c 52 69 6f 74 43 6c 69 65 6e 74 5c 62 69 6e 5c 4c 65 61 67 75 65 43 6c 69 65 6e 74 2e 70 64 62 } //T:\cid\p4\Releases_11_24\LeagueClientCode_X86_Public\15682\tmp\x86-Public-LCU\RiotClient\bin\LeagueClient.pdb  01 00 
		$a_80_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  01 00 
		$a_80_8 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //ShellExecuteW  01 00 
		$a_80_9 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //GetKeyboardLayout  01 00 
		$a_80_10 = {70 77 6c 71 66 75 2e 62 69 7a } //pwlqfu.biz  01 00 
		$a_80_11 = {51 51 42 72 6f 77 73 65 72 2f 39 2e 30 2e 32 35 32 34 2e 34 30 30 } //QQBrowser/9.0.2524.400  00 00 
	condition:
		any of ($a_*)
 
}