
rule Trojan_Win32_Nachhat_A{
	meta:
		description = "Trojan:Win32/Nachhat.A,SIGNATURE_TYPE_PEHSTR,11 00 11 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 63 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 } //01 00  Microcoft Corporation. All rights reserved
		$a_01_1 = {77 69 74 68 20 6f 75 72 20 61 63 74 69 6f 6e 73 20 61 6e 64 } //01 00  with our actions and
		$a_01_2 = {6c 69 76 65 20 69 74 2c 20 6f 72 20 6c 69 76 65 20 77 69 74 68 20 69 74 2e } //01 00  live it, or live with it.
		$a_01_3 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 } //01 00  system32\drivers
		$a_01_4 = {45 52 52 4f 52 5f 49 4e 5f 50 41 52 41 4d 53 5f 49 44 } //01 00  ERROR_IN_PARAMS_ID
		$a_01_5 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_01_6 = {72 76 7a 31 3d 25 64 26 72 76 7a 32 3d 25 2e 31 30 75 } //01 00  rvz1=%d&rvz2=%.10u
		$a_01_7 = {6f 75 74 70 6f 73 74 2e 65 78 65 } //00 00  outpost.exe
	condition:
		any of ($a_*)
 
}