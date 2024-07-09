
rule Backdoor_BAT_Peekserve_B_dha{
	meta:
		description = "Backdoor:BAT/Peekserve.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {33 61 66 38 35 62 62 33 2d 66 63 36 64 2d 34 35 34 35 2d 38 31 33 36 2d 64 64 30 36 33 39 65 63 38 64 34 39 } //3 3af85bb3-fc6d-4545-8136-dd0639ec8d49
		$a_02_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 [0-20] 2e 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 2e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //2
		$a_00_2 = {67 65 74 5f 49 6e 73 74 61 6c 6c 65 72 73 } //1 get_Installers
	condition:
		((#a_00_0  & 1)*3+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}