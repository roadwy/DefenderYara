
rule TrojanDropper_Win32_StoredBt_A{
	meta:
		description = "TrojanDropper:Win32/StoredBt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 3a 72 65 70 65 61 74 5f 64 65 6c } //1 if exist "%s" goto :repeat_del
		$a_01_2 = {72 75 6e 33 32 77 2e 62 61 74 } //1 run32w.bat
		$a_01_3 = {6e 74 25 64 2e 64 6c 6c } //1 nt%d.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}