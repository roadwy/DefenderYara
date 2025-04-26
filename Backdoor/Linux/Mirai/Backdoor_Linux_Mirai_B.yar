
rule Backdoor_Linux_Mirai_B{
	meta:
		description = "Backdoor:Linux/Mirai.B,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {6e 6d 6e 6c 6d 65 76 64 6d } //nmnlmevdm  1
		$a_80_1 = {58 4d 4e 4e 43 50 46 } //XMNNCPF  1
		$a_80_2 = {65 67 76 6e 6d 61 63 6e 6b 72 } //egvnmacnkr  1
		$a_80_3 = {47 4c 43 40 4e 47 } //GLC@NG  1
		$a_80_4 = {51 5b 51 56 47 4f } //Q[QVGO  1
		$a_80_5 = {4c 41 4d 50 50 47 41 56 } //LAMPPGAV  1
		$a_80_6 = {41 4a 57 4c 49 47 46 } //AJWLIGF  1
		$a_01_7 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 61 74 25 25 32 30 2f 65 74 63 2f 70 61 73 73 77 64 } //-1 GET /shell?cat%%20/etc/passwd
		$a_01_8 = {47 45 54 20 2f 73 79 73 74 65 6d 2e 69 6e 69 3f 6c 6f 67 69 6e 75 73 65 26 6c 6f 67 69 6e 70 61 73 } //-1 GET /system.ini?loginuse&loginpas
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_01_7  & 1)*-1+(#a_01_8  & 1)*-1) >=7
 
}
rule Backdoor_Linux_Mirai_B_2{
	meta:
		description = "Backdoor:Linux/Mirai.B,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0b 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 73 74 64 } //1 attack_method_std
		$a_00_1 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 74 63 70 73 79 6e } //1 attack_method_tcpsyn
		$a_00_2 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 2e 63 } //1 attack_method.c
		$a_00_3 = {61 74 74 61 63 6b 5f 67 65 74 5f 6f 70 74 5f 69 6e 74 } //1 attack_get_opt_int
		$a_00_4 = {61 6e 74 69 5f 67 64 62 5f 65 6e 74 72 79 } //1 anti_gdb_entry
		$a_00_5 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 70 6c 61 69 6e 75 64 70 } //1 attack_method_plainudp
		$a_00_6 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 5f 70 6c 61 69 6e 74 63 70 } //1 attack_method_plaintcp
		$a_00_7 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 73 } //1 attack_methods
		$a_00_8 = {61 74 74 61 63 6b 5f 6d 65 74 68 6f 64 73 5f 6c 65 6e } //1 attack_methods_len
		$a_00_9 = {44 65 74 65 72 6d 69 6e 65 64 20 77 65 20 61 6c 72 65 61 64 79 20 68 61 76 65 20 61 20 69 6e 73 74 61 6e 63 65 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 74 68 69 73 20 73 79 73 74 65 6d 21 } //1 Determined we already have a instance running on this system!
		$a_00_10 = {42 69 6e 64 65 64 20 61 6e 64 20 6c 69 73 74 65 6e 69 6e 67 20 6f 6e 20 61 64 64 72 65 73 73 20 25 64 2e 25 64 2e 25 64 2e 25 64 } //1 Binded and listening on address %d.%d.%d.%d
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=3
 
}