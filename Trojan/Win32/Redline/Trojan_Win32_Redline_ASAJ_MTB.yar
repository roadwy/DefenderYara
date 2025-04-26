
rule Trojan_Win32_Redline_ASAJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {03 c6 d3 ee 89 45 ?? c7 05 [0-04] ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 33 75 ?? 81 3d [0-04] 13 02 00 00 75 } //1
		$a_01_1 = {7a 75 76 65 62 65 62 75 63 75 7a 6f 6b 6f 6e 61 76 20 70 75 6a 65 74 6f 74 61 6e 65 6e 6f 76 75 63 69 76 61 62 6f 6b 61 74 65 6b } //1 zuvebebucuzokonav pujetotanenovucivabokatek
		$a_01_2 = {66 61 6b 69 77 61 6d 61 6b 69 62 69 6a 61 62 75 73 6f 63 6f 6c 6f 62 69 6c 65 64 61 74 6f 72 } //1 fakiwamakibijabusocolobiledator
		$a_01_3 = {7a 00 77 00 61 00 66 00 69 00 62 00 61 00 6e 00 61 00 62 00 6f 00 67 00 75 00 63 00 6f 00 73 00 6f 00 77 00 65 00 6a 00 75 00 73 00 65 00 68 00 69 00 66 00 61 00 73 00 69 00 } //1 zwafibanabogucosowejusehifasi
		$a_01_4 = {73 00 75 00 6e 00 61 00 72 00 75 00 68 00 75 00 62 00 61 00 77 00 75 00 6c 00 75 00 79 00 69 00 73 00 61 00 70 00 65 00 64 00 6f 00 64 00 6f 00 } //1 sunaruhubawuluyisapedodo
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}