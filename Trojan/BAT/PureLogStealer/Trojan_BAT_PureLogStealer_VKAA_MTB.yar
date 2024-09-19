
rule Trojan_BAT_PureLogStealer_VKAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.VKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 79 4d 41 62 6d 4f 46 46 75 6a 46 69 65 68 45 50 5a 4f 73 62 56 2e 64 6c 6c } //2 GyMAbmOFFujFiehEPZOsbV.dll
		$a_01_1 = {44 58 42 51 76 57 5a 50 73 6f 69 74 41 67 6c 79 41 71 76 46 } //1 DXBQvWZPsoitAglyAqvF
		$a_01_2 = {44 6b 58 42 50 4e 6b 72 55 49 76 6f 6b 76 41 4b 57 4f 4f 63 4b 4c 2e 64 6c 6c } //1 DkXBPNkrUIvokvAKWOOcKL.dll
		$a_01_3 = {75 6a 65 66 65 51 74 54 53 71 51 45 69 74 6d 67 75 78 58 5a 58 67 46 } //1 ujefeQtTSqQEitmguxXZXgF
		$a_01_4 = {76 79 73 4c 54 77 78 69 67 77 77 4d 47 4a 70 63 51 62 54 50 42 2e 64 6c 6c } //1 vysLTwxigwwMGJpcQbTPB.dll
		$a_01_5 = {6f 56 51 4e 6f 65 54 76 4a 72 64 64 46 6e 75 43 6a 71 42 76 77 62 43 63 } //1 oVQNoeTvJrddFnuCjqBvwbCc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}