
rule Backdoor_Linux_Yakuza_YA_MTB{
	meta:
		description = "Backdoor:Linux/Yakuza.YA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 62 69 6e 73 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 62 69 6e 73 2e 73 68 3b } //5
		$a_01_1 = {5d 20 52 65 73 75 6c 74 20 7c 7c 20 49 50 3a 20 25 73 20 7c 7c 20 50 6f 72 74 3a 20 32 33 20 7c 7c 20 55 73 65 72 6e 61 6d 65 3a 20 25 73 20 7c 7c 20 50 61 73 73 77 6f 72 64 3a 20 25 73 } //1 ] Result || IP: %s || Port: 23 || Username: %s || Password: %s
		$a_01_2 = {5d 20 49 6e 66 65 63 74 69 6e 67 20 7c 7c 20 49 50 3a 20 25 73 20 7c 7c 20 50 6f 72 74 3a 20 32 33 20 7c 7c 20 55 73 65 72 6e 61 6d 65 3a 20 25 73 20 7c 7c 20 50 61 73 73 77 6f 72 64 3a 20 25 73 } //1 ] Infecting || IP: %s || Port: 23 || Username: %s || Password: %s
		$a_01_3 = {5d 20 49 6e 66 65 63 74 69 6f 6e 20 53 75 63 63 65 73 73 2e 20 7c 7c 20 49 50 3a 20 25 73 3a 20 7c 7c 20 50 6f 72 74 3a 20 32 33 20 7c 7c 20 55 73 65 72 6e 61 6d 65 3a 20 25 73 20 7c 7c 20 50 61 73 73 77 6f 72 64 3a 20 25 } //1 ] Infection Success. || IP: %s: || Port: 23 || Username: %s || Password: %
		$a_01_4 = {5d 20 46 61 69 6c 65 64 20 7c 7c 20 49 50 3a 20 25 73 20 7c 7c 20 50 6f 72 74 3a 20 32 33 20 7c 7c 20 55 73 65 72 6e 61 6d 65 3a 20 25 73 20 7c 7c 20 50 61 73 73 77 6f 72 64 3a 20 25 73 } //1 ] Failed || IP: %s || Port: 23 || Username: %s || Password: %s
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}