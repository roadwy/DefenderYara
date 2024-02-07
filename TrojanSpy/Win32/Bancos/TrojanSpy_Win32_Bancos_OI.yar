
rule TrojanSpy_Win32_Bancos_OI{
	meta:
		description = "TrojanSpy:Win32/Bancos.OI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 05 00 "
		
	strings :
		$a_03_0 = {7c 2e 43 33 ff 8d 45 f8 50 8b 45 fc e8 90 01 03 ff 8b d0 2b d7 b9 01 00 00 00 8b 45 fc e8 90 01 03 ff 8b 55 f8 8b c6 e8 90 01 03 ff 47 4b 75 d5 90 00 } //01 00 
		$a_01_1 = {2f 2f 3a 73 70 74 74 68 } //01 00  //:sptth
		$a_01_2 = {69 64 65 6e 74 69 66 69 63 61 } //01 00  identifica
		$a_01_3 = {67 6e 69 6b 6e 61 42 } //02 00  gniknaB
		$a_00_4 = {6f 63 73 65 64 61 72 42 } //02 00  ocsedarB
		$a_01_5 = {6c 69 73 61 72 62 6f 63 6e 61 62 } //02 00  lisarbocnab
		$a_01_6 = {72 62 2e 6d 6f 63 2e 62 62 } //01 00  rb.moc.bb
		$a_00_7 = {72 65 72 6f 6c 70 78 45 20 74 65 6e 72 65 74 6e 49 } //01 00  rerolpxE tenretnI
		$a_01_8 = {53 45 4e 48 41 } //02 00  SENHA
		$a_01_9 = {61 68 6e 65 53 } //00 00  ahneS
	condition:
		any of ($a_*)
 
}