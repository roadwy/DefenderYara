
rule Trojan_Win32_Clipbanker_RF_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ce 00 ff ff ff 46 8a 84 35 90 01 04 88 84 3d 90 01 04 88 8c 35 90 01 04 0f b6 84 3d 90 01 04 8b 4d 90 01 04 03 c2 0f b6 c0 8a 84 05 90 01 04 30 04 19 41 89 4d 90 01 01 3b 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Clipbanker_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Clipbanker.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 74 66 68 6b 6c 6d 6f 70 71 79 75 68 67 6c 6a 6c 6b 6f 70 79 64 73 74 72 65 } //stfhklmopqyuhgljlkopydstre  01 00 
		$a_80_1 = {43 44 6c 67 51 75 6e 46 61 53 5a 32 } //CDlgQunFaSZ2  01 00 
		$a_80_2 = {65 3a 5c 47 5f 4a 4a 4a 5c 6a 6a 6a 32 30 30 38 5c 72 6f 6f 74 32 30 31 37 79 31 31 } //e:\G_JJJ\jjj2008\root2017y11  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Clipbanker_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Clipbanker.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //01 00  GetStartupInfoA
		$a_81_1 = {47 65 74 43 50 49 6e 66 6f } //01 00  GetCPInfo
		$a_81_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //01 00  GetCurrentProcessId
		$a_81_4 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 41 73 46 69 6c 65 54 69 6d 65 } //0a 00  GetSystemTimeAsFileTime
		$a_81_5 = {62 63 31 71 35 6c 67 32 70 76 66 75 39 66 77 64 68 72 6d 63 33 6d 74 65 6d 38 76 76 30 35 65 61 34 78 79 33 34 37 66 68 7a 68 } //0a 00  bc1q5lg2pvfu9fwdhrmc3mtem8vv05ea4xy347fhzh
		$a_81_6 = {33 46 6d 59 31 61 38 48 45 64 4d 56 75 6e 43 41 35 64 65 63 79 68 53 56 54 33 6b 6e 39 64 63 4e 42 70 } //00 00  3FmY1a8HEdMVunCA5decyhSVT3kn9dcNBp
	condition:
		any of ($a_*)
 
}