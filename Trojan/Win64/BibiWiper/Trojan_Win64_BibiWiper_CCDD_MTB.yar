
rule Trojan_Win64_BibiWiper_CCDD_MTB{
	meta:
		description = "Trojan:Win64/BibiWiper.CCDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 52 6f 75 6e 64 20 25 64 } //1 [+] Round %d
		$a_01_1 = {5b 2b 5d 20 50 61 74 68 3a 20 25 73 } //1 [+] Path: %s
		$a_01_2 = {5b 2b 5d 20 43 50 55 20 63 6f 72 65 73 3a 20 25 64 } //1 [+] CPU cores: %d
		$a_01_3 = {54 68 72 65 61 64 73 3a 20 25 64 } //1 Threads: %d
		$a_01_4 = {6c 6c 61 2f 20 74 65 49 75 71 2f 20 73 77 6f 64 61 68 73 20 20 20 65 74 65 6c 65 64 20 6e 69 6d 64 61 73 73 76 20 20 63 2f 20 65 78 65 2e 64 6d 63 } //1 lla/ teIuq/ swodahs   eteled nimdassv  c/ exe.dmc
		$a_01_5 = {74 65 6c 65 64 20 79 70 6f 63 77 6f 64 61 68 73 20 63 69 6d 77 20 63 2f 20 65 78 65 2e 64 6d 63 } //1 teled ypocwodahs cimw c/ exe.dmc
		$a_01_6 = {73 65 72 75 6c 69 61 66 6c 6c 61 65 72 6f 6e 67 69 20 79 63 69 6c 6f 70 73 75 74 61 74 73 74 6f 6f 62 20 7d 74 6c 75 61 66 65 64 7b 20 74 65 73 20 2f 20 74 69 64 65 64 63 62 20 63 20 2f 20 65 78 65 2e 64 6d 63 } //1 seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dmc
		$a_01_7 = {6f 6e 20 64 65 6c 62 61 6e 65 79 72 65 76 6f 63 65 72 20 7d 74 6c 75 61 66 65 64 7b 20 74 65 73 2f 20 74 69 64 65 64 63 62 20 63 2f 20 65 78 65 2e 64 6d 63 } //1 on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dmc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}