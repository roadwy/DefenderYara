
rule VirTool_Win32_TurulC2_A_sms{
	meta:
		description = "VirTool:Win32/TurulC2.A!sms,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_00_0 = {41 67 65 6e 74 44 65 6c 61 79 } //1 AgentDelay
		$a_00_1 = {41 67 65 6e 74 4a 69 74 74 65 72 } //1 AgentJitter
		$a_00_2 = {4b 69 6c 6c 44 61 74 65 } //1 KillDate
		$a_00_3 = {57 6f 72 6b 69 6e 67 48 6f 75 72 73 } //1 WorkingHours
		$a_00_4 = {50 72 6f 66 69 6c 65 } //1 Profile
		$a_81_5 = {63 32 68 68 63 6e 42 7a 62 6d 6c 77 5a 58 49 3d } //1 c2hhcnBzbmlwZXI=
		$a_81_6 = {63 32 68 68 63 6e 42 6b 62 32 31 68 61 57 35 7a 63 48 4a 68 65 51 3d } //1 c2hhcnBkb21haW5zcHJheQ=
		$a_81_7 = {63 32 68 68 63 6e 42 32 61 57 56 33 } //1 c2hhcnB2aWV3
		$a_81_8 = {54 57 39 6b 64 57 78 6c 49 47 68 68 63 79 42 69 5a 57 56 75 49 47 52 6c 63 47 78 76 65 57 56 6b 49 51 3d } //1 TW9kdWxlIGhhcyBiZWVuIGRlcGxveWVkIQ=
		$a_81_9 = {55 6d 56 68 5a 48 6b 67 59 57 35 6b 49 48 64 68 61 58 52 70 62 6d 63 67 5a 6d 39 79 49 47 45 67 59 32 39 74 62 57 46 75 5a 41 3d } //1 UmVhZHkgYW5kIHdhaXRpbmcgZm9yIGEgY29tbWFuZA=
		$a_81_10 = {61 48 52 30 63 } //1 aHR0c
		$a_81_11 = {55 33 64 70 64 47 4e 6f 61 57 35 6e 49 48 52 76 49 48 64 7a } //1 U3dpdGNoaW5nIHRvIHdz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=10
 
}