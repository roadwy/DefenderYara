
rule TrojanSpy_Win32_Gwghost_M{
	meta:
		description = "TrojanSpy:Win32/Gwghost.M,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 47 57 47 4d 54 41 2e 4c 4f 47 } //01 00  C:\GWGMTA.LOG
		$a_00_1 = {63 3a 5c 72 65 63 79 63 6c 65 64 5c } //01 00  c:\recycled\
		$a_00_2 = {63 3a 5c 72 65 63 79 63 6c 65 72 5c } //05 00  c:\recycler\
		$a_02_3 = {8b f0 6a 20 56 6a 00 6a 00 6a 00 68 00 04 00 00 e8 90 01 04 48 03 f0 c6 06 20 46 6a 20 56 6a 00 6a 00 6a 00 68 00 04 00 00 e8 90 01 04 48 03 f0 ba 90 01 04 8b c6 e8 90 01 04 8b f0 6a 00 8d 55 f4 52 8d 85 90 01 04 2b f0 56 50 53 e8 90 01 04 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}