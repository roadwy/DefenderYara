
rule TrojanSpy_Win32_KeyLogger_SM_MTB{
	meta:
		description = "TrojanSpy:Win32/KeyLogger.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //1 taskkill /im
		$a_81_2 = {61 39 65 77 36 34 6a 73 7a 6a 68 37 30 67 74 39 30 39 63 30 6a 69 39 6c 6e 32 62 6d 31 75 6d 32 37 69 30 30 61 33 68 65 70 6a 31 34 34 65 6d 74 68 74 } //1 a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht
		$a_81_3 = {6f 79 37 6f 65 6c 30 31 34 70 67 78 33 72 6e 6d 67 6f 31 66 6c 6f 79 74 74 34 6f 38 65 67 68 61 70 7a 75 6f 6e 37 30 66 68 72 75 30 6c 6e 6c 73 76 6c } //1 oy7oel014pgx3rnmgo1floytt4o8eghapzuon70fhru0lnlsvl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}