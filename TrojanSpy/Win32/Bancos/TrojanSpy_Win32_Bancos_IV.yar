
rule TrojanSpy_Win32_Bancos_IV{
	meta:
		description = "TrojanSpy:Win32/Bancos.IV,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8d 00 ffffff8d 00 08 00 00 64 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {65 6d 69 6e 65 6d } //0a 00  eminem
		$a_00_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //0a 00  explorerbar
		$a_01_3 = {53 54 46 4b 20 4d 75 74 65 78 58 78 } //0a 00  STFK MutexXx
		$a_00_4 = {52 45 41 4c 20 53 2e 49 6e 74 65 72 6e 65 74 3a 20 } //01 00  REAL S.Internet: 
		$a_00_5 = {69 6e 66 6f 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //01 00  info@isbt.com.br
		$a_00_6 = {73 6d 74 70 2e 69 73 62 74 2e 63 6f 6d 2e 62 72 } //01 00  smtp.isbt.com.br
		$a_00_7 = {65 6d 69 6e 65 6d 6a 61 68 32 30 30 35 40 67 6d 61 69 6c 2e 63 6f 6d } //00 00  eminemjah2005@gmail.com
	condition:
		any of ($a_*)
 
}