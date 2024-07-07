
rule Trojan_Win32_Convagent_AZ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 75 62 69 62 6f 4b 6f 7a 6f 71 6f } //1 DubiboKozoqo
		$a_01_1 = {46 6d 44 65 61 6d 4e 5a 53 69 50 5a 42 68 42 45 69 4e 62 45 70 55 } //1 FmDeamNZSiPZBhBEiNbEpU
		$a_01_2 = {4c 59 7a 6b 64 4c 4e 5a 4d 78 4c 72 79 75 66 63 75 48 72 5a 66 53 } //1 LYzkdLNZMxLryufcuHrZfS
		$a_01_3 = {67 4f 4a 75 71 65 73 51 47 49 48 61 72 66 48 44 6d 67 41 70 6b 59 } //1 gOJuqesQGIHarfHDmgApkY
		$a_01_4 = {6b 48 4b 73 43 4a 72 53 45 7a 4f 55 63 48 76 62 44 4a 70 78 6e 78 } //1 kHKsCJrSEzOUcHvbDJpxnx
		$a_01_5 = {66 6f 72 6b 32 2e 64 6c 6c } //1 fork2.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}