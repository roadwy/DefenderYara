
rule TrojanDropper_Win32_Delf_RAG_dll{
	meta:
		description = "TrojanDropper:Win32/Delf.RAG!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 bb 90 01 04 b8 b8 0b 00 00 e8 90 01 04 b8 90 01 04 e8 90 01 04 84 c0 75 07 6a 00 e8 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 a3 90 01 04 83 3d 90 01 04 00 75 09 6a 00 e8 90 01 04 eb 1d b8 90 01 04 ba 02 00 00 00 e8 90 01 04 84 c0 74 0a 68 90 01 04 e8 90 01 04 b9 01 00 00 00 33 d2 b8 02 00 00 00 e8 90 01 04 33 c9 33 d2 b8 04 00 00 00 e8 90 01 04 eb 05 e8 90 01 04 83 3b 03 74 05 83 3b 01 75 f1 68 90 01 04 e8 90 01 04 5b 5d c2 08 00 90 00 } //01 00 
		$a_01_1 = {42 49 54 53 } //01 00  BITS
		$a_01_2 = {73 76 63 68 73 74 2e 65 78 65 } //01 00  svchst.exe
		$a_01_3 = {61 76 69 63 61 70 33 32 2e 64 6c 6c } //01 00  avicap32.dll
		$a_01_4 = {54 68 72 65 61 64 33 32 4e 65 78 74 } //00 00  Thread32Next
	condition:
		any of ($a_*)
 
}