
rule Worm_Win32_Nofupat_A{
	meta:
		description = "Worm:Win32/Nofupat.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 } //1 Microsoft Visual Studio\VB98
		$a_01_1 = {73 63 76 68 6f 73 74 } //1 scvhost
		$a_01_2 = {61 00 73 00 74 00 72 00 79 00 2e 00 65 00 78 00 65 00 } //1 astry.exe
		$a_01_3 = {6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 65 00 78 00 65 00 } //1 network.exe
		$a_01_4 = {75 00 70 00 64 00 61 00 74 00 65 00 5c 00 73 00 63 00 76 00 68 00 6f 00 73 00 74 00 2e 00 76 00 62 00 70 00 } //1 update\scvhost.vbp
		$a_01_5 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 41 } //1 RegOpenKeyExA
		$a_01_6 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //1 RegSetValueExA
		$a_01_7 = {52 65 67 43 6c 6f 73 65 4b 65 79 } //1 RegCloseKey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}