
rule Trojan_Win32_Takil_A{
	meta:
		description = "Trojan:Win32/Takil.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 73 74 6f 70 20 64 68 63 70 2d 63 6c 69 65 6e 74 } //1 net stop dhcp-client
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 20 2f 69 6d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 taskkill /f  /im iexplore.exe
		$a_01_2 = {61 73 73 6f 63 20 2e 65 78 65 3d 57 4d 41 46 69 6c 65 } //1 assoc .exe=WMAFile
		$a_01_3 = {52 65 67 20 41 64 64 20 22 48 4b 43 55 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 4d 6f 75 73 65 22 20 2f 76 20 53 77 61 70 4d 6f 75 73 65 42 75 74 74 6f 6e 73 } //1 Reg Add "HKCU\Control Panel\Mouse" /v SwapMouseButtons
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}