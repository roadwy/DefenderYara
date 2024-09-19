
rule Trojan_BAT_LummaStealer_GPB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 81 1c 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaStealer_GPB_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 4d 73 6d 66 50 76 70 52 54 69 4a 64 44 41 69 70 73 78 } //2 FMsmfPvpRTiJdDAipsx
		$a_01_1 = {62 74 76 48 76 52 78 42 41 6c 59 61 52 50 59 } //2 btvHvRxBAlYaRPY
		$a_01_2 = {5a 4b 4c 4c 44 67 75 4d 7a 44 48 45 } //2 ZKLLDguMzDHE
		$a_01_3 = {66 56 70 4a 52 75 58 55 79 68 47 78 52 68 61 49 63 67 5a 4b } //2 fVpJRuXUyhGxRhaIcgZK
		$a_01_4 = {78 50 6c 6f 79 50 53 70 69 6a 59 6f 53 6e 6c 6b 47 47 43 47 49 67 44 4c } //2 xPloyPSpijYoSnlkGGCGIgDL
		$a_01_5 = {61 6c 6b 6d 4a 49 6f 76 76 4d 52 5a 79 57 5a 61 73 51 4d 75 } //2 alkmJIovvMRZyWZasQMu
		$a_01_6 = {43 6c 76 42 51 4a 43 44 42 56 6e 52 68 6e 72 75 7a 64 47 5a 65 } //2 ClvBQJCDBVnRhnruzdGZe
		$a_01_7 = {58 43 58 62 70 4f 70 64 67 4b 53 52 4e 4e 50 6a 49 56 77 57 59 75 67 41 55 } //2 XCXbpOpdgKSRNNPjIVwWYugAU
		$a_01_8 = {74 4c 72 6d 7a 4a 4d 73 72 57 4f 46 57 6d 6f 4f 78 63 63 74 41 63 43 61 66 7a 41 2e 64 } //1 tLrmzJMsrWOFWmoOxcctAcCafzA.d
		$a_01_9 = {46 67 4c 48 68 64 53 75 4a 48 4f 51 63 56 57 48 5a 66 46 2e 64 } //1 FgLHhdSuJHOQcVWHZfF.d
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=9
 
}