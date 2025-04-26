
rule Trojan_Win64_JaggedToe_D_dha{
	meta:
		description = "Trojan:Win64/JaggedToe.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 6c 61 2f 20 74 65 49 75 71 2f 20 73 77 6f 64 61 68 73 20 20 20 65 74 65 6c 65 64 20 6e 69 6d 64 61 73 73 76 20 20 63 2f 20 65 78 65 2e 64 6d } //1 lla/ teIuq/ swodahs   eteled nimdassv  c/ exe.dm
		$a_81_1 = {73 65 72 75 6c 69 61 66 6c 6c 61 65 72 6f 6e 67 69 20 79 63 69 6c 6f 70 73 75 74 61 74 73 74 6f 6f 62 20 7d 74 6c 75 61 66 65 64 7b 20 74 65 73 20 2f 20 74 69 64 65 64 63 62 20 63 20 2f 20 65 78 65 2e 64 6d } //1 seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dm
		$a_81_2 = {65 74 65 6c 65 64 20 79 70 6f 63 77 6f 64 61 68 73 20 63 69 6d 77 20 63 2f 20 65 78 65 2e 64 6d } //1 eteled ypocwodahs cimw c/ exe.dm
		$a_81_3 = {6f 6e 20 64 65 6c 62 61 6e 65 79 72 65 76 6f 63 65 72 20 7d 74 6c 75 61 66 65 64 7b 20 74 65 73 2f 20 74 69 64 65 64 63 62 20 63 2f 20 65 78 65 2e 64 6d } //1 on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dm
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}