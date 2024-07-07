
rule Backdoor_Linux_IoTReaper{
	meta:
		description = "Backdoor:Linux/IoTReaper,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {6e 6d 6e 6c 6d 65 76 64 6d } //nmnlmevdm  1
		$a_80_1 = {58 4d 4e 4e 43 50 46 } //XMNNCPF  1
		$a_80_2 = {65 67 76 6e 6d 61 63 6e 6b 72 } //egvnmacnkr  1
		$a_80_3 = {47 4c 43 40 4e 47 } //GLC@NG  1
		$a_80_4 = {51 5b 51 56 47 4f } //Q[QVGO  1
		$a_80_5 = {4c 41 4d 50 50 47 41 56 } //LAMPPGAV  1
		$a_80_6 = {41 4a 57 4c 49 47 46 } //AJWLIGF  1
		$a_01_7 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 61 74 25 25 32 30 2f 65 74 63 2f 70 61 73 73 77 64 } //1 GET /shell?cat%%20/etc/passwd
		$a_01_8 = {47 45 54 20 2f 73 79 73 74 65 6d 2e 69 6e 69 3f 6c 6f 67 69 6e 75 73 65 26 6c 6f 67 69 6e 70 61 73 } //1 GET /system.ini?loginuse&loginpas
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}