
rule Trojan_Win32_FakeAV_AK_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 75 6d 70 20 6f 66 20 6f 66 66 73 65 74 } //01 00  Dump of offset
		$a_01_1 = {45 49 50 3d } //01 00  EIP=
		$a_01_2 = {45 46 4c 3d } //01 00  EFL=
		$a_01_3 = {57 72 69 74 65 43 6f 6e 73 6f 6c 65 4f 75 74 70 75 74 43 68 61 72 61 63 74 65 72 41 } //01 00  WriteConsoleOutputCharacterA
		$a_01_4 = {57 72 69 74 65 43 6f 6e 73 6f 6c 65 4f 75 74 70 75 74 41 74 74 72 69 62 75 74 65 } //01 00  WriteConsoleOutputAttribute
		$a_01_5 = {46 6c 75 73 68 43 6f 6e 73 6f 6c 65 49 6e 70 75 74 42 75 66 66 65 72 } //01 00  FlushConsoleInputBuffer
		$a_01_6 = {30 43 30 4d 30 53 30 } //00 00  0C0M0S0
	condition:
		any of ($a_*)
 
}