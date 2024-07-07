
rule Trojan_BAT_NjRat_NEK_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 65 33 38 61 62 64 35 65 2d 30 35 31 63 2d 34 62 36 62 2d 62 38 32 39 2d 31 36 64 39 65 33 63 31 64 61 31 64 } //1 $e38abd5e-051c-4b6b-b829-16d9e3c1da1d
		$a_01_1 = {65 43 44 41 63 65 64 61 76 } //1 eCDAcedav
		$a_01_2 = {65 59 4d 6b 71 36 52 73 78 6a } //1 eYMkq6Rsxj
		$a_01_3 = {65 54 55 6b 70 43 4d 59 38 54 } //1 eTUkpCMY8T
		$a_01_4 = {6d 6b 4c 64 66 38 39 32 33 72 77 45 38 39 7a 52 67 6c 34 73 } //1 mkLdf8923rwE89zRgl4s
		$a_01_5 = {65 35 74 57 32 35 6a 36 38 } //1 e5tW25j68
		$a_01_6 = {65 4e 35 7a 68 4b 5a 4b 64 } //1 eN5zhKZKd
		$a_01_7 = {65 6d 42 73 78 52 4c 57 71 } //1 emBsxRLWq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}