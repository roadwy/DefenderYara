
rule Backdoor_BAT_Rurktar_A{
	meta:
		description = "Backdoor:BAT/Rurktar.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {52 00 43 00 53 00 55 00 2e 00 65 00 78 00 65 00 } //1 RCSU.exe
		$a_01_1 = {52 00 43 00 53 00 2e 00 6c 00 6f 00 67 00 } //1 RCS.log
		$a_01_2 = {5c 00 52 00 5f 00 43 00 5f 00 53 00 2e 00 69 00 6e 00 69 00 } //1 \R_C_S.ini
		$a_01_3 = {5c 00 52 00 43 00 53 00 2e 00 69 00 6e 00 69 00 } //1 \RCS.ini
		$a_01_4 = {38 00 30 00 2e 00 37 00 38 00 2e 00 32 00 35 00 31 00 2e 00 31 00 33 00 38 00 } //1 80.78.251.138
		$a_01_5 = {38 00 30 00 2e 00 37 00 38 00 2e 00 32 00 35 00 31 00 2e 00 31 00 34 00 38 00 } //1 80.78.251.148
		$a_01_6 = {38 00 39 00 2e 00 32 00 35 00 30 00 2e 00 31 00 34 00 36 00 2e 00 31 00 30 00 39 00 } //1 89.250.146.109
		$a_01_7 = {74 00 79 00 70 00 65 00 2a 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 } //1 type*updater
		$a_01_8 = {3f 00 72 00 65 00 63 00 69 00 76 00 65 00 66 00 69 00 6c 00 65 00 2a 00 } //1 ?recivefile*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}