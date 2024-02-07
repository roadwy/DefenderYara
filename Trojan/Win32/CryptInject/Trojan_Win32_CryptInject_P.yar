
rule Trojan_Win32_CryptInject_P{
	meta:
		description = "Trojan:Win32/CryptInject.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 00 6d 00 73 00 75 00 58 00 45 00 56 00 74 00 3d 00 23 00 2b 00 25 00 44 00 72 00 42 00 26 00 70 00 3e 00 2f 00 71 00 } //01 00  GmsuXEVt=#+%DrB&p>/q
		$a_01_1 = {5c 47 6c 65 61 6e 65 64 5c 70 75 72 65 63 61 6c 6c 5c 77 69 6e 33 32 70 36 2e 70 64 62 } //01 00  \Gleaned\purecall\win32p6.pdb
		$a_01_2 = {74 00 68 00 65 00 6f 00 66 00 66 00 2e 00 61 00 73 00 6b 00 73 00 50 00 42 00 50 00 38 00 77 00 68 00 69 00 63 00 68 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 } //00 00  theoff.asksPBP8whichextensions
	condition:
		any of ($a_*)
 
}