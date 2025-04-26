
rule Trojan_Win32_GuLoader_RSE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 66 65 6a 6c 74 61 73 74 6e 69 6e 67 5c 66 65 6d 64 6f 62 6c 65 72 5c 71 75 61 73 69 70 61 72 74 69 63 6c 65 } //1 \fejltastning\femdobler\quasiparticle
		$a_81_1 = {39 39 5c 69 6e 68 61 62 69 6c 69 74 65 74 73 73 70 72 67 73 6d 61 61 6c 65 74 2e 74 69 63 } //1 99\inhabilitetssprgsmaalet.tic
		$a_81_2 = {72 65 6b 6f 6d 70 65 6e 73 65 72 65 73 2e 6a 70 67 } //1 rekompenseres.jpg
		$a_81_3 = {75 66 6f 72 73 76 61 72 6c 69 67 68 65 64 73 20 72 65 67 75 6c 61 74 6f 72 79 20 6f 76 65 72 6b 6e 6f 77 69 6e 67 } //1 uforsvarligheds regulatory overknowing
		$a_81_4 = {75 6e 64 65 72 67 72 75 6e 64 73 6b 75 6c 74 75 72 65 72 6e 65 } //1 undergrundskulturerne
		$a_81_5 = {75 6e 63 6f 6e 66 6f 72 6d 69 74 79 20 6e 6f 6e 69 6d 70 75 74 61 74 69 76 65 6c 79 2e 65 78 65 } //1 unconformity nonimputatively.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}