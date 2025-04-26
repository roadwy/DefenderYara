
rule Backdoor_Linux_Ventir_A{
	meta:
		description = "Backdoor:Linux/Ventir.A,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 61 72 67 65 74 55 52 4c 3a 00 73 65 74 53 6f 75 72 63 65 55 52 4c 3a 00 73 65 74 4b 65 79 3a } //1 慔杲瑥剕㩌猀瑥潓牵散剕㩌猀瑥敋㩹
		$a_01_1 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 72 65 77 65 62 } //1 killall -9 reweb
		$a_00_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 63 6f 6e 66 69 67 20 57 48 45 52 45 20 69 64 3d 31 } //1 SELECT * FROM config WHERE id=1
		$a_00_3 = {67 65 74 63 6f 6e 66 69 67 } //1 getconfig
		$a_01_4 = {00 25 40 2f 75 70 64 61 74 65 00 } //1
		$a_01_5 = {48 4f 4f 4b 20 53 54 41 52 54 21 } //1 HOOK START!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}