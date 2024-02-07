
rule Trojan_Win64_Cobaltstrike_DH_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 71 38 63 77 58 68 37 5e 33 64 2a 65 46 63 52 55 34 54 47 63 51 32 3e 31 78 3e 26 54 57 3f 74 29 37 70 53 34 52 2a } //01 00  hq8cwXh7^3d*eFcRU4TGcQ2>1x>&TW?t)7pS4R*
		$a_81_1 = {78 66 61 64 71 4b 4b 63 62 47 66 54 61 45 } //01 00  xfadqKKcbGfTaE
		$a_81_2 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //01 00  GetCommandLineA
		$a_81_3 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //01 00  NoNetConnectDisconnect
		$a_81_4 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //01 00  NoRecentDocsHistory
		$a_81_5 = {4e 6f 44 72 69 76 65 73 } //01 00  NoDrives
		$a_81_6 = {4e 6f 52 75 6e } //00 00  NoRun
	condition:
		any of ($a_*)
 
}