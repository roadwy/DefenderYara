
rule TrojanSpy_Win32_Bancos_KA{
	meta:
		description = "TrojanSpy:Win32/Bancos.KA,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {4a 75 6e 69 6f 72 53 61 6e 74 6f 73 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  JuniorSantos@gmail.com
		$a_01_2 = {70 6f 72 72 61 76 63 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  porravc@gmail.com
		$a_01_3 = {49 6e 66 65 63 74 20 56 65 6e 68 6f 20 64 65 20 } //01 00  Infect Venho de 
		$a_01_4 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_5 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //01 00  OpenClipboard
		$a_01_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  GetClipboardData
		$a_01_7 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //00 00  InternetGetConnectedState
	condition:
		any of ($a_*)
 
}