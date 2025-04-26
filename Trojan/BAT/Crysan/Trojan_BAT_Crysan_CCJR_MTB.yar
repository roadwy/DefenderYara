
rule Trojan_BAT_Crysan_CCJR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 44 41 63 74 49 51 37 55 37 53 53 34 65 62 4a 53 37 45 61 4f 41 3d 3d } //2 tDActIQ7U7SS4ebJS7EaOA==
		$a_81_1 = {48 66 67 4f 71 34 6a 55 49 67 45 3d } //1 HfgOq4jUIgE=
		$a_81_2 = {63 3a 5c 74 65 6d 70 5c 41 73 73 65 6d 62 6c 79 2e 65 78 65 } //1 c:\temp\Assembly.exe
		$a_81_3 = {42 63 69 66 6a 68 7a 76 75 77 } //1 Bcifjhzvuw
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}