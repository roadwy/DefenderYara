
rule Virus_BAT_Kaczcore{
	meta:
		description = "Virus:BAT/Kaczcore,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4b 61 63 7a 43 4f 52 45 5f 56 69 72 75 73 } //KaczCORE_Virus  1
		$a_80_1 = {4b 6f 6e 74 61 6b 74 20 44 43 3a 20 6b 61 63 7a 6b 61 79 74 31 30 } //Kontakt DC: kaczkayt10  1
		$a_80_2 = {7b 22 66 69 6c 65 73 22 3a 7b 22 68 61 73 6c 6f 2e 74 78 74 22 3a 7b 22 63 6f 6e 74 65 6e 74 22 3a 22 53 54 41 52 54 22 7d 7d 7d } //{"files":{"haslo.txt":{"content":"START"}}}  1
		$a_80_3 = {4d 61 73 7a 79 6e 61 3a } //Maszyna:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}