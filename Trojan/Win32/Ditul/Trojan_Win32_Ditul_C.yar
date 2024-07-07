
rule Trojan_Win32_Ditul_C{
	meta:
		description = "Trojan:Win32/Ditul.C,SIGNATURE_TYPE_PEHSTR,1a 00 18 00 08 00 00 "
		
	strings :
		$a_01_0 = {30 11 83 c1 01 80 39 00 75 f6 } //20
		$a_01_1 = {51 77 61 76 29 45 63 61 6a 70 3e 24 49 6b 7e 6d 68 68 65 2b 31 2a 34 24 2c 53 6d 6a 60 6b 73 77 3f 24 51 3f 24 53 6d } //1 Qwav)Ecajp>$Ik~mhhe+1*4$,Smj`ksw?$Q?$Sm
		$a_01_2 = {47 65 67 6c 61 29 47 6b 6a 70 76 6b 68 3e 24 6a 6b 29 67 65 67 6c 61 } //1 Gegla)Gkjpvkh>$jk)gegla
		$a_01_3 = {47 6b 6a 6a 61 67 70 6d 6b 6a 3e 24 47 68 6b 77 61 } //1 Gkjjagpmkj>$Ghkwa
		$a_01_4 = {52 65 66 65 72 65 72 3a 20 74 65 73 74 } //1 Referer: test
		$a_01_5 = {56 7a 7a 7e 7c 70 2f 35 40 66 70 67 28 } //1 Vzz~|p/5@fpg(
		$a_01_6 = {41 77 56 77 70 67 75 42 60 7b 64 7b 7e 77 75 77 } //1 AwVwpguB`{d{~wuw
		$a_01_7 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 } //1 elementclient.e
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=24
 
}