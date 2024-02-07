
rule Trojan_Win32_Tedy_MA_MTB{
	meta:
		description = "Trojan:Win32/Tedy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 83 c0 01 89 45 f0 83 7d f0 03 7d 1a 8b 4d c4 03 4d e0 8b 55 f0 8a 44 15 e4 88 01 8b 4d e0 83 c1 01 89 4d e0 eb } //05 00 
		$a_01_1 = {64 65 73 6b 74 6f 70 2e 64 } //05 00  desktop.d
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //02 00  DllRegisterServer
		$a_01_3 = {65 78 63 75 6c 70 61 74 6f 72 69 6c 79 } //02 00  exculpatorily
		$a_01_4 = {68 65 6d 6f 70 68 61 67 79 } //02 00  hemophagy
		$a_01_5 = {68 79 67 69 6f 6c 6f 67 69 73 74 } //02 00  hygiologist
		$a_01_6 = {6f 6e 63 6f 6d 65 74 72 69 63 } //00 00  oncometric
	condition:
		any of ($a_*)
 
}