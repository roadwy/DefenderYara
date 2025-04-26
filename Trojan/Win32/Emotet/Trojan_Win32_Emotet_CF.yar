
rule Trojan_Win32_Emotet_CF{
	meta:
		description = "Trojan:Win32/Emotet.CF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 64 75 62 71 61 2e 70 64 62 } //2 odubqa.pdb
		$a_01_1 = {54 72 6f 6e 65 74 6f 6e 2e 70 64 62 } //2 Troneton.pdb
		$a_01_2 = {4e 6a 68 5a 57 4e 5f 63 33 34 65 } //1 NjhZWN_c34e
		$a_01_3 = {4f 00 44 00 42 00 43 00 20 00 28 00 33 00 2e 00 30 00 29 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 20 00 66 00 6f 00 72 00 20 00 44 00 42 00 61 00 73 00 65 00 } //1 ODBC (3.0) driver for DBase
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Emotet_CF_2{
	meta:
		description = "Trojan:Win32/Emotet.CF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {55 54 b9 04 00 00 00 89 1d ?? ?? 40 00 83 f9 03 74 20 58 01 c8 8f 05 ?? ?? 40 00 a3 ?? ?? 40 00 39 e0 0f 84 } //7
		$a_03_1 = {83 f8 04 74 03 89 45 fc c3 5a 01 ca 85 c0 89 15 ?? a5 40 00 } //8
		$a_00_2 = {53 68 75 74 64 6f 77 6e 42 6c 6f 63 6b 52 65 61 73 6f 6e 44 65 73 74 72 6f 79 } //1 ShutdownBlockReasonDestroy
		$a_00_3 = {46 6c 75 73 68 50 72 6f 63 65 73 73 57 72 69 74 65 42 75 66 66 65 72 73 } //1 FlushProcessWriteBuffers
		$a_00_4 = {50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 66 66 66 66 66 } //3 PSXPSXPSXPSXPSXPSXfffff
		$a_00_5 = {57 69 6e 53 43 61 72 64 2e 64 6c 6c } //3 WinSCard.dll
	condition:
		((#a_03_0  & 1)*7+(#a_03_1  & 1)*8+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*3+(#a_00_5  & 1)*3) >=10
 
}