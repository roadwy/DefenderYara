
rule TrojanSpy_Win32_Banker_DQ{
	meta:
		description = "TrojanSpy:Win32/Banker.DQ,SIGNATURE_TYPE_PEHSTR_EXT,ffffff98 08 ffffffd0 07 04 00 00 ffffffe8 03 "
		
	strings :
		$a_02_0 = {c6 00 30 a1 90 01 02 48 00 ba 90 01 02 47 00 e8 90 01 02 f8 ff e8 90 01 02 f9 ff dd 1d 90 01 02 48 00 9b ff 35 90 01 02 48 00 ff 35 90 01 02 48 00 8d 45 fc e8 90 01 02 f9 ff 8b 55 fc b8 90 01 02 48 00 e8 90 01 02 f8 ff 68 90 01 02 47 00 ff 35 90 01 02 48 00 68 90 01 02 47 00 8d 45 f8 ba 03 00 00 00 e8 90 01 02 f8 ff 8b 45 f8 90 00 } //e8 03 
		$a_02_1 = {33 d2 8b 83 90 01 01 04 00 00 e8 90 01 02 fb ff e9 90 01 02 00 00 e8 90 01 02 f9 ff d8 25 90 01 02 47 00 dd 1d 90 01 02 48 00 9b ff 35 90 01 02 48 00 ff 35 90 01 02 48 00 8d 45 f4 e8 90 01 02 f9 ff 8b 55 f4 b8 90 01 02 48 00 e8 90 01 02 f8 ff 68 90 01 02 47 00 ff 35 90 01 02 48 00 68 90 01 02 47 00 8d 45 f0 ba 03 00 00 00 90 00 } //64 00 
		$a_00_2 = {77 69 6e 6c 6f 67 } //64 00  winlog
		$a_00_3 = {6d 73 62 63 62 2e 65 78 65 } //00 00  msbcb.exe
	condition:
		any of ($a_*)
 
}