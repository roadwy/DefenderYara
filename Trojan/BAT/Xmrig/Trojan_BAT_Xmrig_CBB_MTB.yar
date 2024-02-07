
rule Trojan_BAT_Xmrig_CBB_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.CBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_81_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_81_1 = {43 68 72 6f 6d 65 } //01 00  Chrome
		$a_81_2 = {73 48 78 2b 54 41 36 53 4b 78 31 2b 4d 32 62 47 4b 44 35 4c 4c 67 3d 3d } //01 00  sHx+TA6SKx1+M2bGKD5LLg==
		$a_81_3 = {4d 46 61 6b 6f 2f 70 43 58 4a 2f 6f 78 2f 36 76 4b 65 49 76 6f 41 3d 3d } //01 00  MFako/pCXJ/ox/6vKeIvoA==
		$a_81_4 = {51 2f 31 4d 75 51 67 31 4f 78 4b 31 4c 62 41 51 78 39 6c 45 45 67 3d 3d } //01 00  Q/1MuQg1OxK1LbAQx9lEEg==
		$a_81_5 = {74 6c 54 61 42 49 6e 4b 78 39 78 30 44 51 7a 79 66 62 6f 56 67 41 3d 3d } //01 00  tlTaBInKx9x0DQzyfboVgA==
		$a_81_6 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //00 00  Rfc2898DeriveBytes
	condition:
		any of ($a_*)
 
}