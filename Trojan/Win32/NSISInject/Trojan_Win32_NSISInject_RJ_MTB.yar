
rule Trojan_Win32_NSISInject_RJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 00 5a 62 02 6a 00 ff 55 } //1
		$a_01_1 = {81 e1 03 09 01 00 81 e2 61 12 00 00 35 d3 6f 00 00 81 c2 c9 55 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_NSISInject_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d8 59 59 85 db 74 21 8b f3 2b f7 d1 fe 03 f6 56 57 8b 7d f4 57 } //1
		$a_01_1 = {0f b7 16 66 85 d2 74 11 83 fa 22 74 05 66 89 14 47 40 83 c6 02 3b c1 7c e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_NSISInject_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 09 3d 00 6a 54 8b 45 e4 50 e8 [0-10] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 [0-20] 6a 40 68 00 30 00 00 8b 55 94 52 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_RJ_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 46 6f 72 74 79 6e 64 65 64 65 5c 4e 6f 6e 61 63 74 69 76 65 73 } //1 Software\Fortyndede\Nonactives
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 55 70 72 6f 66 65 73 73 69 6f 6e 65 6c 5c 54 65 73 6b 65 66 75 6c 64 } //1 Software\Uprofessionel\Teskefuld
		$a_01_2 = {50 6f 73 69 74 73 2e 6c 6e 6b } //1 Posits.lnk
		$a_01_3 = {54 73 61 74 74 69 6e 65 5c 56 69 65 73 2e 69 6e 69 } //1 Tsattine\Vies.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_RJ_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 64 00 73 00 6e 00 75 00 73 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //1 Indsnuses.ini
		$a_01_1 = {53 00 6c 00 61 00 61 00 66 00 65 00 6a 00 6c 00 65 00 6e 00 73 00 2e 00 48 00 6c 00 65 00 } //1 Slaafejlens.Hle
		$a_01_2 = {52 00 65 00 67 00 6e 00 69 00 6e 00 67 00 73 00 61 00 72 00 74 00 73 00 2e 00 69 00 6e 00 69 00 } //1 Regningsarts.ini
		$a_01_3 = {48 00 6f 00 75 00 73 00 65 00 63 00 6f 00 61 00 74 00 65 00 6e 00 65 00 31 00 31 00 34 00 2e 00 69 00 6e 00 69 00 } //1 Housecoatene114.ini
		$a_01_4 = {45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 62 00 79 00 67 00 67 00 65 00 72 00 69 00 65 00 72 00 6e 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //1 Elementbyggeriernes.ini
		$a_01_5 = {4b 00 6e 00 61 00 70 00 70 00 65 00 6e 00 61 00 61 00 6c 00 73 00 68 00 6f 00 76 00 65 00 64 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 Knappenaalshoveder.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}