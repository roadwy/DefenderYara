
rule Trojan_Win32_Bifrose_SP_MTB{
	meta:
		description = "Trojan:Win32/Bifrose.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 6a 4e ff d7 8b d0 8d 8d 60 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 5c ff ff ff ff d6 50 6a 4d ff d7 8b d0 8d 8d 58 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 54 ff ff ff ff d6 50 6a 52 ff d7 8b d0 8d 8d 50 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 4c ff ff ff ff d6 50 6a 55 ff d7 8b d0 8d 8d 48 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 44 ff ff ff ff d6 50 6a 35 ff d7 8b d0 8d 8d 40 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 3c ff ff ff ff d6 50 6a 53 ff d7 8b d0 8d 8d 38 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 34 ff ff ff ff d6 50 6a 52 ff d7 8b d0 8d 8d 30 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 2c ff ff ff ff d6 50 6a 55 ff d7 8b d0 8d 8d 28 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 24 ff ff ff ff d6 50 6a 73 } //3
		$a_01_1 = {61 00 64 00 73 00 4e 00 4f 00 59 00 69 00 64 00 47 00 56 00 70 00 49 00 63 00 } //1 adsNOYidGVpIc
		$a_01_2 = {6c 00 53 00 6b 00 56 00 61 00 41 00 6f 00 6d 00 67 00 79 00 76 00 52 00 6f 00 4d 00 52 00 } //1 lSkVaAomgyvRoMR
		$a_01_3 = {4c 00 72 00 41 00 42 00 7a 00 45 00 70 00 69 00 71 00 54 00 68 00 67 00 77 00 41 00 43 00 } //1 LrABzEpiqThgwAC
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}