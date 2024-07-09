
rule Backdoor_BAT_CrimsonRat_A_MTB{
	meta:
		description = "Backdoor:BAT/CrimsonRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 09 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 7c } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run|  10
		$a_81_1 = {3c 46 49 4c 45 5f 41 55 54 4f 3c 7c } //10 <FILE_AUTO<|
		$a_80_2 = {73 65 74 5f 43 6c 69 65 6e 74 53 69 7a 65 } //set_ClientSize  1
		$a_80_3 = {63 73 63 72 65 65 6e } //cscreen  1
		$a_80_4 = {63 6c 70 69 6e 67 } //clping  1
		$a_80_5 = {63 61 70 53 63 72 65 65 6e } //capScreen  1
		$a_80_6 = {69 6e 66 6f 3d 75 73 65 72 7c } //info=user|  1
		$a_80_7 = {63 6c 69 65 6e 74 73 5f 64 61 74 61 7c } //clients_data|  1
		$a_02_8 = {5c 6f 62 6a 5c 44 65 62 75 67 [0-14] 2e 70 64 62 } //1
	condition:
		((#a_80_0  & 1)*10+(#a_81_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_02_8  & 1)*1) >=24
 
}