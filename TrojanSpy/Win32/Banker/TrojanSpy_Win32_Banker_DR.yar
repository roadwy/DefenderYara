
rule TrojanSpy_Win32_Banker_DR{
	meta:
		description = "TrojanSpy:Win32/Banker.DR,SIGNATURE_TYPE_PEHSTR,16 00 16 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 00 43 00 45 00 46 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00 } //10 \CEF\VBBHO.vbp
		$a_01_1 = {67 62 69 65 68 63 65 66 2e 64 6c 6c } //10 gbiehcef.dll
		$a_01_2 = {53 68 64 6f 63 77 76 2e 64 6c 6c } //10 Shdocwv.dll
		$a_01_3 = {53 00 63 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 } //5 Scpad.exe
		$a_01_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 2e 00 63 00 61 00 69 00 78 00 61 00 2e 00 67 00 6f 00 76 00 2e 00 62 00 72 00 2f 00 53 00 49 00 49 00 42 00 43 00 2f 00 69 00 6e 00 64 00 65 00 78 00 } //5 https://internetbanking.caixa.gov.br/SIIBC/index
		$a_01_5 = {6d 73 76 62 76 6d 36 30 2e 64 6c 6c } //1 msvbvm60.dll
		$a_01_6 = {7a 6f 6d 62 69 65 5f 67 65 74 74 79 70 65 69 6e 66 6f 63 6f 75 6e 74 } //1 zombie_gettypeinfocount
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=22
 
}