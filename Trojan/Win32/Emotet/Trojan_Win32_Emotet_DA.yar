
rule Trojan_Win32_Emotet_DA{
	meta:
		description = "Trojan:Win32/Emotet.DA,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 36 73 39 53 2e 70 64 62 } //01 00  g6s9S.pdb
		$a_01_1 = {49 67 72 53 4f 35 71 45 68 48 58 2e 70 64 62 } //01 00  IgrSO5qEhHX.pdb
		$a_01_2 = {47 2e 59 63 2e 77 63 72 2e 70 64 62 } //01 00  G.Yc.wcr.pdb
		$a_01_3 = {78 38 36 5c 52 75 6e 44 6c 6c 2e 70 64 62 } //02 00  x86\RunDll.pdb
		$a_01_4 = {50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 55 } //00 00  PSXPSXPSXPSXPSXPSXU
	condition:
		any of ($a_*)
 
}