
rule Trojan_Win32_Tnega_MV_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {73 71 6c 69 74 65 33 2e 64 6c 6c } //1 sqlite3.dll
		$a_81_1 = {5f 65 78 63 65 70 74 5f 68 61 6e 64 6c 65 72 33 } //1 _except_handler3
		$a_81_2 = {5f 58 63 70 74 46 69 6c 74 65 72 } //1 _XcptFilter
		$a_81_3 = {5f 61 64 6a 75 73 74 5f 66 64 69 76 } //1 _adjust_fdiv
		$a_81_4 = {5f 5f 73 65 74 75 73 65 72 6d 61 74 68 65 72 72 } //1 __setusermatherr
		$a_81_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 43 50 4d } //1 SOFTWARE\Borland\Delphi\CPM
		$a_81_6 = {5c 56 65 72 73 69 6f 6e 49 6e 64 65 70 65 6e 64 65 6e 74 50 72 6f 67 49 44 } //1 \VersionIndependentProgID
		$a_81_7 = {44 62 72 65 61 6b } //1 Dbreak
		$a_81_8 = {44 65 66 65 6e 64 65 72 43 53 50 2e 64 6c 6c } //1 DefenderCSP.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}