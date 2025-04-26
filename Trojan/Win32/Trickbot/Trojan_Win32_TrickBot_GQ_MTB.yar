
rule Trojan_Win32_TrickBot_GQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {61 00 66 c7 [0-02] 73 00 66 c7 [0-02] 77 00 66 c7 [0-02] 68 00 66 c7 [0-02] 6f 00 66 c7 [0-02] 6f 00 66 c7 [0-02] 6b 00 66 c7 [0-02] 2e 00 66 c7 [0-02] 64 00 66 c7 [0-02] 6c 00 66 c7 [0-02] 6c 00 } //1
		$a_02_1 = {33 d2 5b 8d 0c [0-02] 8b [0-02] f7 [0-02] 8b 44 [0-02] 8a [0-02] 30 01 46 3b 74 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickBot_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {6a 40 68 00 10 00 00 57 6a 00 ff d3 } //1
		$a_81_1 = {5c 44 4c 4c 50 4f 52 54 41 42 4c 45 58 38 36 5c 33 32 5c 52 65 6c 65 61 73 65 5c 64 6c 6c 33 32 73 6d 70 6c 2e 70 64 62 } //1 \DLLPORTABLEX86\32\Release\dll32smpl.pdb
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_3 = {4b 72 61 73 49 6f 64 57 } //1 KrasIodW
		$a_81_4 = {61 73 73 62 31 } //1 assb1
		$a_81_5 = {69 6d 69 74 34 } //1 imit4
		$a_81_6 = {6c 74 72 69 64 70 } //1 ltridp
		$a_81_7 = {31 2e 64 6c 6c } //1 1.dll
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}