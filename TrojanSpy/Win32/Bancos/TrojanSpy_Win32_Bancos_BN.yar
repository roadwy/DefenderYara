
rule TrojanSpy_Win32_Bancos_BN{
	meta:
		description = "TrojanSpy:Win32/Bancos.BN,SIGNATURE_TYPE_PEHSTR,ffffff97 00 ffffff97 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {4b 65 72 6e 65 6c 6c 41 70 70 73 } //10 KernellApps
		$a_01_2 = {5c 73 76 73 68 6f 73 74 69 2e 65 78 65 } //10 \svshosti.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 62 61 6e 6b 6c 69 6e 65 2e 69 74 61 75 } //10 http://bankline.itau
		$a_01_4 = {72 62 2e 6d 6f 63 2e 62 65 77 65 72 75 63 65 73 6c 61 65 72 2e 77 77 77 } //10 rb.moc.beweruceslaer.www
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {5c 53 79 6d 61 6e 74 65 63 20 53 68 61 72 65 64 5c 63 63 41 70 70 2e 65 78 65 } //1 \Symantec Shared\ccApp.exe
		$a_01_7 = {5c 4e 6f 72 74 6f 6e 20 53 79 73 74 65 6d 57 6f 72 6b 73 5c 4e 6f 72 74 6f 6e 20 41 6e 74 69 56 69 72 75 73 5c 4e 61 76 61 70 77 33 32 2e 65 78 65 } //1 \Norton SystemWorks\Norton AntiVirus\Navapw32.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=151
 
}