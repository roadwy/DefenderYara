
rule PWS_Win32_Graftor_S_MSR{
	meta:
		description = "PWS:Win32/Graftor.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 32 68 68 65 44 52 30 62 32 39 73 63 79 35 6a 62 32 30 76 55 32 46 32 5a 55 5a 76 63 6e 64 68 63 6d 52 6c 63 69 39 7a 59 58 5a 6c 4c 6e 42 6f 63 41 3d 3d } //01 00  aHR0cDovL2hheDR0b29scy5jb20vU2F2ZUZvcndhcmRlci9zYXZlLnBocA==
		$a_01_1 = {2f 00 68 00 74 00 6d 00 6c 00 2d 00 73 00 61 00 6e 00 64 00 62 00 6f 00 78 00 65 00 64 00 } //01 00  /html-sandboxed
		$a_01_2 = {43 48 41 4e 47 45 5f 50 41 53 53 57 4f 52 44 } //01 00  CHANGE_PASSWORD
		$a_01_3 = {73 61 55 73 65 72 6e 61 6d 65 } //01 00  saUsername
		$a_01_4 = {43 6f 6f 6b 69 65 43 6f 6c 6c 65 63 74 69 6f 6e } //00 00  CookieCollection
	condition:
		any of ($a_*)
 
}