
rule Trojan_Win32_Guloader_VB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 0a 81 f6 [0-05] 89 34 08 83 e9 [0-05] 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_VB_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_01_1 = {44 00 75 00 62 00 6c 00 61 00 6e 00 74 00 65 00 72 00 6e 00 65 00 73 00 } //1 Dublanternes
		$a_01_2 = {62 00 65 00 73 00 67 00 65 00 6c 00 73 00 65 00 73 00 74 00 69 00 64 00 65 00 6e 00 } //1 besgelsestiden
		$a_01_3 = {54 00 75 00 62 00 65 00 72 00 6b 00 75 00 6c 00 69 00 6e 00 73 00 } //1 Tuberkulins
		$a_01_4 = {46 00 72 00 69 00 63 00 61 00 6e 00 64 00 65 00 6c 00 6c 00 65 00 38 00 } //1 Fricandelle8
		$a_01_5 = {41 00 61 00 6c 00 65 00 6b 00 76 00 61 00 62 00 62 00 65 00 6e 00 31 00 } //1 Aalekvabben1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Guloader_VB_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_01_1 = {54 00 4f 00 4c 00 56 00 41 00 41 00 52 00 53 00 46 00 44 00 53 00 45 00 4c 00 53 00 44 00 41 00 47 00 45 00 4e 00 45 00 53 00 } //1 TOLVAARSFDSELSDAGENES
		$a_01_2 = {48 00 59 00 50 00 41 00 4c 00 47 00 45 00 53 00 49 00 43 00 } //1 HYPALGESIC
		$a_01_3 = {65 00 6e 00 61 00 6d 00 6f 00 75 00 72 00 65 00 64 00 6e 00 65 00 73 00 73 00 } //1 enamouredness
		$a_01_4 = {46 00 6f 00 72 00 68 00 61 00 6e 00 64 00 6c 00 69 00 6e 00 67 00 73 00 70 00 61 00 72 00 74 00 6e 00 65 00 72 00 6e 00 65 00 } //1 Forhandlingspartnerne
		$a_01_5 = {49 00 6e 00 64 00 6c 00 65 00 6d 00 6d 00 65 00 64 00 65 00 33 00 } //1 Indlemmede3
		$a_01_6 = {61 00 67 00 75 00 72 00 6b 00 65 00 74 00 69 00 64 00 65 00 72 00 73 00 } //1 agurketiders
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Guloader_VB_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_01_1 = {49 00 55 00 37 00 37 00 6f 00 63 00 42 00 4f 00 38 00 4e 00 41 00 51 00 6f 00 64 00 33 00 76 00 6c 00 46 00 57 00 70 00 6a 00 35 00 59 00 79 00 65 00 6f 00 30 00 50 00 42 00 31 00 31 00 33 00 36 00 } //1 IU77ocBO8NAQod3vlFWpj5Yyeo0PB1136
		$a_01_2 = {4d 00 73 00 4e 00 50 00 34 00 59 00 69 00 74 00 55 00 6d 00 41 00 71 00 4d 00 4c 00 43 00 54 00 54 00 35 00 56 00 6c 00 48 00 77 00 68 00 36 00 } //1 MsNP4YitUmAqMLCTT5VlHwh6
		$a_01_3 = {57 00 4f 00 49 00 56 00 65 00 70 00 4f 00 68 00 76 00 52 00 52 00 38 00 65 00 37 00 38 00 74 00 30 00 45 00 66 00 67 00 78 00 44 00 4b 00 46 00 52 00 6b 00 56 00 42 00 4c 00 48 00 56 00 79 00 73 00 6c 00 30 00 72 00 31 00 33 00 34 00 } //1 WOIVepOhvRR8e78t0EfgxDKFRkVBLHVysl0r134
		$a_01_4 = {49 00 47 00 53 00 66 00 4a 00 61 00 63 00 67 00 56 00 36 00 35 00 4f 00 5a 00 5a 00 6d 00 6f 00 66 00 75 00 6c 00 39 00 35 00 56 00 73 00 55 00 50 00 55 00 35 00 78 00 48 00 6e 00 4c 00 76 00 33 00 4b 00 77 00 4a 00 59 00 31 00 38 00 34 00 } //1 IGSfJacgV65OZZmoful95VsUPU5xHnLv3KwJY184
		$a_01_5 = {75 00 4d 00 68 00 72 00 53 00 58 00 5a 00 4e 00 78 00 31 00 4e 00 77 00 39 00 34 00 68 00 71 00 41 00 76 00 32 00 69 00 52 00 6e 00 47 00 4e 00 63 00 5a 00 39 00 4b 00 78 00 48 00 61 00 33 00 31 00 } //1 uMhrSXZNx1Nw94hqAv2iRnGNcZ9KxHa31
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}