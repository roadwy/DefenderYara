
rule TrojanSpy_Win32_Gamol_A{
	meta:
		description = "TrojanSpy:Win32/Gamol.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 50 6c 61 7a 61 2e 65 78 65 } //01 00  GamePlaza.exe
		$a_01_1 = {61 74 3d 67 65 74 6d 62 26 73 31 33 3d 25 73 } //01 00  at=getmb&s13=%s
		$a_01_2 = {7a 71 3d 25 73 26 7a 66 3d 25 73 26 7a 75 3d 25 73 26 7a 70 3d 25 73 26 7a 6d 7a 3d 25 73 26 6c 3d 25 64 26 7a 6a 62 3d 25 64 26 7a 63 6a 3d 25 64 26 7a 63 6b 3d 25 73 26 70 69 6e 3d 25 73 26 7a 7a 62 3d 25 73 26 70 61 72 61 3d 25 73 26 62 73 6d 62 3d 25 64 26 64 32 30 3d 25 73 3a 25 73 20 25 73 3a 25 73 20 25 73 3a 25 73 26 68 73 6e 3d 25 73 } //00 00  zq=%s&zf=%s&zu=%s&zp=%s&zmz=%s&l=%d&zjb=%d&zcj=%d&zck=%s&pin=%s&zzb=%s&para=%s&bsmb=%d&d20=%s:%s %s:%s %s:%s&hsn=%s
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}