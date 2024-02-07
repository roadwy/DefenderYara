
rule Trojan_Win32_Danabot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Danabot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 0a 00 "
		
	strings :
		$a_81_0 = {63 3a 5c 50 72 65 70 61 72 65 5c 43 6f 6e 74 72 6f 6c 5c 57 6f 72 6b 5c 62 6f 78 5c 68 65 61 72 64 2e 70 64 62 } //01 00  c:\Prepare\Control\Work\box\heard.pdb
		$a_81_1 = {43 6c 69 65 6e 74 20 68 6f 6f 6b 20 66 72 65 65 20 66 61 69 6c 75 72 65 2e } //01 00  Client hook free failure.
		$a_81_2 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 45 78 } //01 00  GetLocaleInfoEx
		$a_81_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //01 00  GetTickCount64
		$a_81_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //01 00  VirtualProtectEx
		$a_81_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_6 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //01 00  GetStartupInfoW
		$a_81_7 = {47 65 74 43 50 49 6e 66 6f } //01 00  GetCPInfo
		$a_81_8 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 45 78 57 } //00 00  GetModuleHandleExW
	condition:
		any of ($a_*)
 
}