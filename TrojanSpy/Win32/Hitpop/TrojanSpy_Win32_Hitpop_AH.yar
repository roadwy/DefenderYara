
rule TrojanSpy_Win32_Hitpop_AH{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AH,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 69 74 70 6f 70 } //02 00  hitpop
		$a_01_1 = {77 65 62 68 69 74 6c 6f 67 74 6d 70 2e 64 61 74 } //01 00  webhitlogtmp.dat
		$a_01_2 = {67 67 5f 63 6f 75 6e 74 } //01 00  gg_count
		$a_01_3 = {70 6d 5f 63 6f 75 6e 74 } //01 00  pm_count
		$a_01_4 = {41 56 50 2e 42 75 74 74 6f 6e } //01 00  AVP.Button
		$a_01_5 = {61 63 74 69 76 65 2e 61 73 70 3f 76 65 72 3d } //01 00  active.asp?ver=
		$a_01_6 = {26 61 64 64 72 65 73 73 3d } //01 00  &address=
		$a_01_7 = {4b 52 65 67 45 78 2e 65 78 65 } //01 00  KRegEx.exe
		$a_01_8 = {4b 56 58 50 2e 6b 78 70 } //00 00  KVXP.kxp
	condition:
		any of ($a_*)
 
}