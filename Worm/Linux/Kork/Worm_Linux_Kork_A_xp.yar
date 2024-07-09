
rule Worm_Linux_Kork_A_xp{
	meta:
		description = "Worm:Linux/Kork.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 3a 72 3a 63 3a 61 3a 6f 3a 70 3a 77 3a 6b } //1 t:r:c:a:o:p:w:k
		$a_01_1 = {53 45 43 6c 70 64 20 76 69 63 74 69 6d } //1 SEClpd victim
		$a_03_2 = {76 69 63 74 69 6d [0-04] 62 72 75 74 65 [0-04] 2d 74 20 74 79 70 65 20 5b 2d 6f 20 6f 66 66 73 65 74 5d } //1
		$a_01_3 = {4c 50 52 6e 67 2f 6c 70 64 } //1 LPRng/lpd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}