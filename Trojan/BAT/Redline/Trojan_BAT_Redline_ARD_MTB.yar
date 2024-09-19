
rule Trojan_BAT_Redline_ARD_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 06 0b 1b 8d d1 00 00 01 0c 16 0d 2b 0e 09 06 08 09 1b 09 59 6f 47 00 00 0a 58 0d 09 1b 32 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Redline_ARD_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 91 11 00 11 03 91 58 20 00 01 00 00 5d 13 07 20 03 00 00 00 7e ?? 01 00 04 7b } //1
		$a_03_1 = {11 00 11 02 11 00 11 03 91 9c 20 01 00 00 00 7e ?? 01 00 04 7b ?? 00 00 04 39 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Redline_ARD_MTB_3{
	meta:
		description = "Trojan:BAT/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 59 72 4a 61 45 70 59 63 54 55 51 69 52 44 43 54 57 41 75 68 41 69 62 2e 64 6c 6c } //1 SYrJaEpYcTUQiRDCTWAuhAib.dll
		$a_01_1 = {5a 48 4b 46 54 4d 6c 4d 5a 73 43 4d 6e 59 53 48 4f 41 46 56 54 67 6e 55 5a 50 2e 64 6c 6c } //1 ZHKFTMlMZsCMnYSHOAFVTgnUZP.dll
		$a_01_2 = {66 59 6f 42 54 62 6f 6c 6b 44 58 74 56 70 45 75 77 50 70 73 75 76 71 62 65 2e 64 6c 6c } //1 fYoBTbolkDXtVpEuwPpsuvqbe.dll
		$a_01_3 = {4e 54 5a 75 51 5a 7a 4a 6f 65 52 48 4a 54 75 } //1 NTZuQZzJoeRHJTu
		$a_01_4 = {54 00 65 00 73 00 6c 00 61 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 54 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 } //1 Tesla Corporation Trademark
		$a_01_5 = {61 30 66 34 34 37 65 66 2d 35 39 37 61 2d 34 62 37 30 2d 38 38 37 62 2d 65 38 30 32 39 31 66 63 33 31 37 32 } //1 a0f447ef-597a-4b70-887b-e80291fc3172
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}