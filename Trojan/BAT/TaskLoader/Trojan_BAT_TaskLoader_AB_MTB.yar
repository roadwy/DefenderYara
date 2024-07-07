
rule Trojan_BAT_TaskLoader_AB_MTB{
	meta:
		description = "Trojan:BAT/TaskLoader.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {16 13 0d 38 4b 05 00 00 11 0d 1c 62 13 0e 16 13 0f 38 3e 00 00 00 06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d } //10
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {73 69 68 6f 73 74 } //3 sihost
		$a_81_3 = {48 6f 73 74 20 66 6f 72 20 53 79 73 74 65 6d 20 49 6e 66 6f } //3 Host for System Info
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}