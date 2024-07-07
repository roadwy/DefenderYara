
rule Backdoor_Linux_Gafgyt_BL_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 61 77 75 64 70 } //1 rawudp
		$a_00_1 = {6b 69 6c 6c 61 74 74 6b } //1 killattk
		$a_00_2 = {62 6f 74 6b 69 6c 6c } //1 botkill
		$a_00_3 = {6f 55 7a 69 6c 53 7a 31 34 78 64 32 6d 30 4c 68 53 64 59 31 54 50 33 55 72 51 5a 4a 6e 74 68 4c 75 6d 45 55 53 67 4b 32 79 75 71 42 44 42 6c 63 53 67 33 57 67 67 55 65 66 45 6e 52 54 4b } //1 oUzilSz14xd2m0LhSdY1TP3UrQZJnthLumEUSgK2yuqBDBlcSg3WggUefEnRTK
		$a_00_4 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_00_5 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}