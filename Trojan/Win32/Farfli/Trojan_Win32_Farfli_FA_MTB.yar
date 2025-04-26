
rule Trojan_Win32_Farfli_FA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 10 a7 e5 9c a1 8d 1d 98 4a aa 65 31 14 be 31 a4 b3 80 41 ef e6 74 a8 84 50 25 27 a9 73 de 71 70 } //1
		$a_01_1 = {63 3a 5c 25 73 2e 65 78 65 } //1 c:\%s.exe
		$a_01_2 = {44 6f 56 69 72 75 73 53 63 61 6e } //1 DoVirusScan
		$a_01_3 = {68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 31 30 30 2e 38 33 } //1 http://192.168.100.83
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 2e 63 6f 6d } //1 http://www.1.com
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}