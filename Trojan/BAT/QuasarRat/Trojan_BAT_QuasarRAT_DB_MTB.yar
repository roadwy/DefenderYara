
rule Trojan_BAT_QuasarRAT_DB_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff88 00 ffffff88 00 0b 00 00 "
		
	strings :
		$a_81_0 = {53 68 61 72 70 42 65 61 63 6f 6e 2d 6d 61 73 74 65 72 } //100 SharpBeacon-master
		$a_81_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10 DllCanUnloadNow
		$a_03_2 = {68 00 74 00 74 00 70 00 [0-01] 3a 00 2f 00 2f 00 [0-64] 2e 00 65 00 78 00 65 00 } //10
		$a_03_3 = {68 74 74 70 [0-01] 3a 2f 2f [0-64] 2e 65 78 65 } //10
		$a_81_4 = {61 6d 73 69 2e 64 6c 6c } //10 amsi.dll
		$a_01_5 = {41 4d 53 49 42 79 70 61 73 73 } //1 AMSIBypass
		$a_01_6 = {50 61 74 63 68 } //1 Patch
		$a_01_7 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_8 = {46 69 6e 64 41 64 64 72 65 73 73 } //1 FindAddress
		$a_01_9 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_10 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_81_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=136
 
}