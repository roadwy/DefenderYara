
rule Trojan_Win32_Qakbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 45 12 eb 06 1a 41 ?? 33 04 5f 03 db 4b 03 d2 81 e8 e8 ef 00 00 33 c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 69 c8 af d7 8b 94 24 ?? ?? ?? ?? 81 c2 f2 29 a5 87 66 89 8c 24 ?? ?? ?? ?? 39 [0-04] 72 } //1
		$a_03_1 = {81 e1 8e 46 1b 50 89 8c 24 ?? ?? ?? ?? 8b 44 c2 ?? 89 44 24 ?? 66 8b 74 24 ?? 66 89 b4 24 ?? ?? ?? ?? 8b 44 24 ?? c7 84 24 ?? ?? ?? ?? f8 19 ab 5d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_00_0 = {4b 03 da 03 f8 33 fe 89 95 34 f0 ff ff 2b fb 33 cf fe c1 81 ff 3b 16 00 00 75 } //10
		$a_80_1 = {42 75 67 72 65 70 6f 72 74 46 65 61 74 75 72 65 72 65 71 75 65 73 74 4b 6e 6f 77 6e 49 73 73 75 65 73 31 } //BugreportFeaturerequestKnownIssues1  1
		$a_80_2 = {75 73 65 72 6e 61 6d 65 5f 74 78 74 } //username_txt  1
		$a_80_3 = {70 61 73 73 77 6f 72 64 5f 74 78 74 } //password_txt  1
		$a_80_4 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 57 } //LookupAccountSidW  1
		$a_80_5 = {73 74 61 67 65 72 5f 31 2e 64 6c 6c } //stager_1.dll  1
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=15
 
}