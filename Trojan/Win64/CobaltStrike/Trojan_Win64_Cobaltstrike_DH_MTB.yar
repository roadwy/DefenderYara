
rule Trojan_Win64_Cobaltstrike_DH_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c1 41 83 e1 ?? 47 8a 0c 08 44 32 0c 01 48 ff c0 44 88 48 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_DH_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 71 38 63 77 58 68 37 5e 33 64 2a 65 46 63 52 55 34 54 47 63 51 32 3e 31 78 3e 26 54 57 3f 74 29 37 70 53 34 52 2a } //1 hq8cwXh7^3d*eFcRU4TGcQ2>1x>&TW?t)7pS4R*
		$a_81_1 = {78 66 61 64 71 4b 4b 63 62 47 66 54 61 45 } //1 xfadqKKcbGfTaE
		$a_81_2 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //1 GetCommandLineA
		$a_81_3 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_81_4 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 NoRecentDocsHistory
		$a_81_5 = {4e 6f 44 72 69 76 65 73 } //1 NoDrives
		$a_81_6 = {4e 6f 52 75 6e } //1 NoRun
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}