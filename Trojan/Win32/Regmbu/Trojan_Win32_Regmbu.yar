
rule Trojan_Win32_Regmbu{
	meta:
		description = "Trojan:Win32/Regmbu,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 73 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 70 68 70 3f 71 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d 26 70 61 67 69 6e 61 3d 31 26 72 78 70 3d 32 30 } //4 cas.com/search.php?q={searchTerms}&pagina=1&rxp=20
		$a_01_1 = {53 65 61 72 63 68 53 63 6f 70 65 73 5c 7b 41 33 34 35 38 37 32 33 34 2d 41 57 45 52 2d 33 32 35 36 2d 35 54 59 36 2d 31 32 45 44 45 52 47 54 59 35 36 38 7d } //2 SearchScopes\{A34587234-AWER-3256-5TY6-12EDERGTY568}
		$a_01_2 = {31 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 31 65 61 72 63 68 31 63 6f 70 65 73 } //1 1oftware\Microsoft\Internet Explorer\1earch1copes
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 62 75 31 63 61 31 2e 63 6f 6d 2f 69 6e 64 65 78 70 2e 70 68 70 3f 69 64 3d } //1 http://www.mbu1ca1.com/indexp.php?id=
		$a_01_4 = {42 47 20 57 69 6e 64 6f 77 73 32 00 49 45 58 50 4c 4f 52 45 52 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}