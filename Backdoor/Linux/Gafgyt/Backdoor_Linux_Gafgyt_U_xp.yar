
rule Backdoor_Linux_Gafgyt_U_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.U!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 44 50 42 59 50 41 53 53 } //1 UDPBYPASS
		$a_00_1 = {64 34 6d 51 61 73 44 53 48 36 } //1 d4mQasDSH6
		$a_00_2 = {59 61 6b 75 7a 61 20 5d 20 49 6e 66 65 63 74 69 6e 67 20 7c 7c 20 49 50 3a 20 25 73 20 7c 7c 20 50 6f 72 74 3a 20 32 33 20 7c 7c 20 55 73 65 72 6e 61 6d 65 3a 20 25 73 20 7c 7c 20 50 61 73 73 77 6f 72 64 3a 20 25 73 } //1 Yakuza ] Infecting || IP: %s || Port: 23 || Username: %s || Password: %s
		$a_02_3 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 90 02 10 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 90 02 10 2e 73 68 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}