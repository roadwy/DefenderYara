
rule VirTool_Win64_ProcessProtectionHijack_A{
	meta:
		description = "VirTool:Win64/ProcessProtectionHijack.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 0f b6 d1 ?? ?? ?? ?? ?? ?? ?? 8b c2 83 e0 0f 48 63 c8 41 8b 84 88 4c 36 00 00 49 03 c0 } //1
		$a_01_1 = {4c 89 7c 24 58 48 8b cb 48 89 44 24 50 f3 0f 7f 44 24 64 44 89 7c 24 74 c7 44 24 60 04 00 00 00 e8 } //1
		$a_01_2 = {4c 89 7c 24 48 4c 89 7c 24 58 4d 8b f0 f3 0f 7f 44 24 64 44 89 7c 24 74 48 8b ea 48 8b d9 c7 44 24 60 04 00 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}