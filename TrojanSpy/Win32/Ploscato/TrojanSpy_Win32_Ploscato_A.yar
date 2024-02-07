
rule TrojanSpy_Win32_Ploscato_A{
	meta:
		description = "TrojanSpy:Win32/Ploscato.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 5b 00 00 00 b8 cc cc cc cc f3 ab b9 09 00 00 00 be 90 01 04 8d 7d d4 f3 a5 a4 8a 45 e0 88 85 7c ff ff ff 90 00 } //01 00 
		$a_01_1 = {7a 3a 5c 50 72 6f 6a 65 63 74 73 5c 52 65 73 63 61 74 6f 72 5c 75 70 6c 6f 61 64 65 72 5c 44 65 62 75 67 5c 73 63 68 65 63 6b 2e 70 64 62 } //00 00  z:\Projects\Rescator\uploader\Debug\scheck.pdb
	condition:
		any of ($a_*)
 
}