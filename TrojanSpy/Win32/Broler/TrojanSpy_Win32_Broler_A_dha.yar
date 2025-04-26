
rule TrojanSpy_Win32_Broler_A_dha{
	meta:
		description = "TrojanSpy:Win32/Broler.A!dha,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6d 61 72 2e 65 78 65 } //5 taskmar.exe
		$a_01_1 = {5c 64 6f 63 5f 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 44 6f 63 44 6c 6c 2e 70 64 62 } //1 \doc_dll\Release\DocDll.pdb
		$a_01_2 = {5c 50 72 6f 6a 65 63 74 73 5c 45 78 70 61 6e 64 5c 52 65 6c 65 61 73 65 5c 45 78 70 61 6e 64 2e 70 64 62 } //1 \Projects\Expand\Release\Expand.pdb
		$a_01_3 = {52 53 44 53 } //5 RSDS
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5) >=11
 
}