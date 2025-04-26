
rule Backdoor_Win64_Turla_A_MTB{
	meta:
		description = "Backdoor:Win64/Turla.A!MTB,SIGNATURE_TYPE_PEHSTR,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6a 61 76 61 73 63 72 69 70 74 2f 76 69 65 77 2e 70 68 70 } //10 /javascript/view.php
		$a_01_1 = {6e 6f 5f 73 65 72 76 65 72 5f 68 69 6a 61 63 6b } //10 no_server_hijack
		$a_01_2 = {35 32 37 39 43 33 31 30 2d 43 41 32 32 2d 45 41 41 31 2d 46 45 34 39 2d 43 33 41 36 41 32 32 41 46 43 38 32 } //10 5279C310-CA22-EAA1-FE49-C3A6A22AFC82
		$a_01_3 = {61 6c 6c 6f 77 3d 2a 65 76 65 72 79 6f 6e 65 } //1 allow=*everyone
		$a_01_4 = {2a 2e 69 6e 66 } //1 *.inf
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=32
 
}