
rule Ransom_MacOS_Filecoder_YB_MTB{
	meta:
		description = "Ransom:MacOS/Filecoder.YB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {74 6f 69 64 69 65 76 69 74 63 65 66 66 65 2f 6c 69 62 70 65 72 73 69 73 74 2f 72 65 6e 6e 75 72 2e 63 } //1 toidievitceffe/libpersist/rennur.c
		$a_00_1 = {2f 74 6f 69 64 69 65 76 69 74 63 65 66 66 65 2f 6c 69 62 70 65 72 73 69 73 74 2f 70 65 72 73 69 73 74 2e 63 } //1 /toidievitceffe/libpersist/persist.c
		$a_00_2 = {65 69 5f 72 6f 6f 74 67 61 69 6e 65 72 5f 65 6c 65 76 61 74 65 } //1 ei_rootgainer_elevate
		$a_00_3 = {49 4e 46 45 43 54 4f 52 20 4d 41 49 4e } //1 INFECTOR MAIN
		$a_00_4 = {67 65 74 5f 70 72 6f 63 65 73 73 5f 6c 69 73 74 } //1 get_process_list
		$a_00_5 = {63 61 72 76 65 72 5f 6d 61 69 6e } //1 carver_main
		$a_00_6 = {76 69 72 74 75 61 6c 5f 6d 63 68 6e } //1 virtual_mchn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}