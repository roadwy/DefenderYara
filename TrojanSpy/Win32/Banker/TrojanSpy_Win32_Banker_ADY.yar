
rule TrojanSpy_Win32_Banker_ADY{
	meta:
		description = "TrojanSpy:Win32/Banker.ADY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 3d 3d 3d 3d 3d 3d 74 61 62 65 6c 61 66 69 6d 3d 3d 3d 3d 3d 3d } //01 00  =======tabelafim======
		$a_01_1 = {3d 3d 3d 3d 3d 3d 3d 62 61 63 6b 75 70 3d 3d 3d 3d 3d 3d } //01 00  =======backup======
		$a_01_2 = {73 65 6e 68 61 20 31 20 3d } //01 00  senha 1 =
		$a_01_3 = {61 67 63 63 5f 62 6b 20 3d } //01 00  agcc_bk =
		$a_01_4 = {72 6f 74 69 6e 61 3d } //01 00  rotina=
		$a_01_5 = {72 61 64 65 73 63 6f 00 49 45 46 72 61 6d 65 } //02 00 
		$a_03_6 = {6d 61 71 75 69 6e 61 74 3d 00 90 02 10 68 6f 72 61 3d 00 90 02 10 64 61 64 6f 73 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}