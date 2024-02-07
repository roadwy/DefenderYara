
rule Trojan_Win32_Zlob_I{
	meta:
		description = "Trojan:Win32/Zlob.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 13 8a 45 00 3c 61 7c 0c 3c 66 7f 08 0f be c0 83 e8 60 eb 02 33 c0 03 e8 8b c5 89 6c 24 30 } //02 00 
		$a_01_1 = {99 b9 64 00 00 00 f7 f9 be 08 00 00 00 83 fa 50 0f } //01 00 
		$a_01_2 = {2b c6 d1 f8 8d 74 42 02 3b f2 b8 03 00 00 00 76 57 85 c0 7e 12 83 ee 02 66 83 3e 2e 75 03 83 e8 01 3b f2 77 ec 85 c0 75 3f } //01 00 
		$a_00_3 = {5f 00 41 00 44 00 31 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 52 00 } //00 00  _AD1CompleteR
	condition:
		any of ($a_*)
 
}