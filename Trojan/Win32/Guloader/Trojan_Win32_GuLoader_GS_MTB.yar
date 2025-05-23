
rule Trojan_Win32_GuLoader_GS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 73 00 6d 00 61 00 74 00 65 00 72 00 69 00 61 00 6c 00 65 00 72 00 6e 00 65 00 73 00 } //1 Informationsmaterialernes
		$a_01_1 = {43 00 55 00 52 00 49 00 4f 00 4c 00 4f 00 47 00 49 00 43 00 41 00 4c 00 4c 00 59 00 } //1 CURIOLOGICALLY
		$a_01_2 = {48 00 59 00 50 00 45 00 52 00 50 00 49 00 54 00 55 00 49 00 54 00 41 00 52 00 59 00 } //1 HYPERPITUITARY
		$a_01_3 = {4c 00 69 00 74 00 74 00 65 00 72 00 61 00 74 00 75 00 72 00 73 00 6f 00 65 00 67 00 6e 00 69 00 6e 00 67 00 73 00 70 00 72 00 6f 00 63 00 65 00 73 00 39 00 } //1 Litteratursoegningsproces9
		$a_01_4 = {70 00 72 00 64 00 69 00 6b 00 61 00 74 00 6f 00 6d 00 64 00 62 00 6e 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 } //1 prdikatomdbningerne
		$a_01_5 = {73 00 79 00 67 00 65 00 73 00 69 00 6b 00 72 00 69 00 6e 00 67 00 73 00 6b 00 6f 00 6e 00 74 00 6f 00 72 00 73 00 } //1 sygesikringskontors
		$a_01_6 = {50 00 68 00 69 00 6c 00 6f 00 73 00 6f 00 70 00 68 00 69 00 63 00 6f 00 6a 00 75 00 72 00 69 00 73 00 74 00 69 00 63 00 } //1 Philosophicojuristic
		$a_01_7 = {45 00 6c 00 65 00 6b 00 74 00 72 00 6f 00 73 00 76 00 65 00 6a 00 73 00 6e 00 69 00 6e 00 67 00 65 00 6e 00 } //1 Elektrosvejsningen
		$a_01_8 = {54 00 4f 00 4c 00 56 00 41 00 41 00 52 00 53 00 46 00 44 00 53 00 45 00 4c 00 53 00 44 00 41 00 47 00 45 00 4e 00 45 00 53 00 } //1 TOLVAARSFDSELSDAGENES
		$a_00_9 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}