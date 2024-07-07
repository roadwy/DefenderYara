
rule Trojan_Win32_SpyNoon_RR_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {5c 70 72 6f 6f 66 69 6e 67 5c 63 6f 6e 66 6f 75 6e 64 } //1 \proofing\confound
		$a_01_1 = {66 75 6f 61 70 63 79 77 68 64 74 68 } //1 fuoapcywhdth
		$a_01_2 = {7a 6a 71 65 6e 67 76 67 73 67 } //1 zjqengvgsg
		$a_01_3 = {6f 79 68 6b 6f 67 73 73 78 64 6a 77 6a } //1 oyhkogssxdjwj
		$a_01_4 = {70 74 71 76 79 63 76 63 74 67 7a 65 } //1 ptqvycvctgze
		$a_01_5 = {32 37 30 35 39 } //1 27059
		$a_01_6 = {73 6e 6e 69 75 62 66 73 69 6c } //1 snniubfsil
		$a_01_7 = {7a 68 71 74 61 76 6f 67 72 77 71 } //1 zhqtavogrwq
		$a_01_8 = {73 71 6f 67 6e 6b 6b 67 73 6c 78 } //1 sqognkkgslx
		$a_01_9 = {67 78 63 79 69 6d 75 77 68 6a 6f 6b } //1 gxcyimuwhjok
		$a_01_10 = {65 77 6e 62 6c 7a 6b 71 6d 6b 76 69 } //1 ewnblzkqmkvi
		$a_01_11 = {5c 63 6c 6f 61 6b 5c 63 6f 6e 66 6f 75 6e 64 2e 72 61 } //1 \cloak\confound.ra
		$a_01_12 = {6f 78 71 6c 78 66 7a 7a 65 6b } //1 oxqlxfzzek
		$a_01_13 = {53 4f 46 54 57 41 52 45 5c 68 65 6d 6c 6f 63 6b 5c 66 69 65 73 74 61 } //1 SOFTWARE\hemlock\fiesta
		$a_01_14 = {5c 72 65 66 75 73 65 73 5c 65 6e 73 6c 61 76 65 64 2e 68 74 6d 6c } //1 \refuses\enslaved.html
		$a_01_15 = {43 3a 5c 54 45 4d 50 5c 77 68 6c 75 64 62 67 76 } //1 C:\TEMP\whludbgv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}