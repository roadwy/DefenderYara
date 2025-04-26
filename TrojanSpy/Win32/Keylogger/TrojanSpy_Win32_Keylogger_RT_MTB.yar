
rule TrojanSpy_Win32_Keylogger_RT_MTB{
	meta:
		description = "TrojanSpy:Win32/Keylogger.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 41 53 45 61 48 52 30 63 44 6f 76 4c 32 35 6c 64 32 78 76 63 32 68 79 5a 57 55 75 65 48 6c 36 4c 33 64 76 63 6d 73 76 61 32 56 75 62 6e 6b 7a 4c 6e 42 6f 63 41 3d 3d 59 54 59 44 } //1 AASEaHR0cDovL25ld2xvc2hyZWUueHl6L3dvcmsva2VubnkzLnBocA==YTYD
		$a_81_1 = {61 48 52 30 63 44 6f 76 4c 33 52 6c 63 6d 56 69 61 57 35 75 59 57 68 70 59 32 4d 75 59 32 78 31 59 69 39 7a 5a 57 4d 76 61 32 39 76 62 43 35 30 65 48 51 3d } //1 aHR0cDovL3RlcmViaW5uYWhpY2MuY2x1Yi9zZWMva29vbC50eHQ=
		$a_81_2 = {50 41 44 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 77 71 65 75 75 69 77 65 5b 58 58 58 58 58 58 58 5d } //1 PADwqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwewqeuuiwe[XXXXXXX]
		$a_81_3 = {6f 79 37 6f 65 6c 30 31 34 70 67 78 33 72 6e 6d 67 6f 31 66 6c 6f 79 74 74 34 6f 38 65 67 68 61 70 7a 75 6f 6e 37 30 66 68 72 75 30 6c 6e 6c 73 76 6c } //1 oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}