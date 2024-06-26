
rule TrojanSpy_Win32_Banker_APD{
	meta:
		description = "TrojanSpy:Win32/Banker.APD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 47 33 4e 44 34 3a } //01 00  AG3ND4:
		$a_01_1 = {43 30 4e 54 34 54 3a } //01 00  C0NT4T:
		$a_01_2 = {43 45 4c 55 4c 41 52 3a } //01 00  CELULAR:
		$a_01_3 = {53 33 4e 48 34 36 3a } //01 00  S3NH46:
		$a_01_4 = {53 33 4e 48 34 38 3a } //01 00  S3NH48:
		$a_01_5 = {53 33 4e 48 34 34 3a } //01 00  S3NH44:
		$a_01_6 = {43 41 52 54 41 4f 3a } //01 00  CARTAO:
		$a_01_7 = {43 43 56 20 44 4f 20 43 41 52 54 41 4f 3a } //01 00  CCV DO CARTAO:
		$a_01_8 = {63 68 72 6f 6d 65 2e 65 78 65 } //01 00  chrome.exe
		$a_01_9 = {47 62 70 53 56 2e 65 78 65 } //01 00  GbpSV.exe
		$a_01_10 = {30 32 33 2d 20 43 6f 6e 74 61 20 43 41 49 58 41 20 46 } //00 00  023- Conta CAIXA F
		$a_00_11 = {5d 04 00 00 } //65 67 
	condition:
		any of ($a_*)
 
}