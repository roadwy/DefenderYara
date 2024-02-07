
rule TrojanSpy_Win32_SSonce_C{
	meta:
		description = "TrojanSpy:Win32/SSonce.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6b 65 79 6c 6f 67 2e 64 61 74 } //01 00  \keylog.dat
		$a_01_1 = {7c 44 49 52 23 30 23 00 } //01 00  䑼剉〣#
		$a_00_2 = {73 74 75 62 70 61 74 68 00 } //01 00 
		$a_00_3 = {5b 73 68 69 66 74 5d } //00 00  [shift]
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_SSonce_C_2{
	meta:
		description = "TrojanSpy:Win32/SSonce.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 03 00 "
		
	strings :
		$a_03_0 = {ba e9 03 00 00 e8 90 01 04 8d 95 90 01 01 fb ff ff b9 e9 03 00 00 8b 45 90 01 01 e8 90 01 04 8b d8 8b 45 90 01 01 80 78 0c 00 90 00 } //01 00 
		$a_01_1 = {05 06 00 00 00 00 00 00 00 00 00 01 00 00 07 08 09 0a 04 00 00 00 00 00 02 03 00 00 00 00 00 00 00 00 00 00 0b } //01 00 
		$a_01_2 = {75 4b 65 79 4c 6f 67 67 65 72 } //01 00  uKeyLogger
		$a_01_3 = {50 63 6e 52 61 77 69 6e 70 75 74 } //01 00  PcnRawinput
		$a_01_4 = {75 45 6e 63 72 79 70 74 69 6f 6e } //01 00  uEncryption
		$a_01_5 = {75 50 61 72 73 65 72 } //01 00  uParser
		$a_01_6 = {5f 53 6f 63 6b 65 74 55 6e 69 74 } //01 00  _SocketUnit
		$a_01_7 = {75 52 65 6d 6f 74 65 53 68 65 6c 6c } //00 00  uRemoteShell
	condition:
		any of ($a_*)
 
}