
rule TrojanSpy_Win32_Rumish_C{
	meta:
		description = "TrojanSpy:Win32/Rumish.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 20 79 61 2e 72 75 } //1 er\iexplore.exe" ya.ru
		$a_01_1 = {65 78 70 6c 57 53 5c 72 75 6e 65 78 70 6c 5c 52 65 6c 65 61 73 65 5c 70 73 74 68 6f 73 74 2e 70 64 62 } //1 explWS\runexpl\Release\psthost.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}