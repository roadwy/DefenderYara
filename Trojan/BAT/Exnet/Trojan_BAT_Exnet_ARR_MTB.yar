
rule Trojan_BAT_Exnet_ARR_MTB{
	meta:
		description = "Trojan:BAT/Exnet.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_81_0 = {3c 72 67 34 4b 63 45 41 64 33 68 68 45 7a 6e 31 37 73 58 54 36 3e 62 5f 5f 36 5f 30 } //7 <rg4KcEAd3hhEzn17sXT6>b__6_0
		$a_81_1 = {55 34 30 78 4e 47 4d 74 36 4e 66 6f 6f 35 4e 36 71 } //3 U40xNGMt6Nfoo5N6q
		$a_81_2 = {5a 67 45 48 67 57 50 4a 2e 65 78 65 } //10 ZgEHgWPJ.exe
		$a_81_3 = {71 77 5a 46 79 4d 72 66 73 61 44 42 74 76 50 79 32 45 31 37 } //6 qwZFyMrfsaDBtvPy2E17
		$a_81_4 = {3c 72 67 34 4b 63 45 41 64 33 68 68 45 7a 6e 31 37 73 58 54 36 3e 62 5f 5f 32 } //4 <rg4KcEAd3hhEzn17sXT6>b__2
	condition:
		((#a_81_0  & 1)*7+(#a_81_1  & 1)*3+(#a_81_2  & 1)*10+(#a_81_3  & 1)*6+(#a_81_4  & 1)*4) >=30
 
}