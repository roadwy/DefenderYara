
rule Backdoor_Linux_FireBack_A_xp{
	meta:
		description = "Backdoor:Linux/FireBack.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 61 64 6c 79 6e 6f 73 65 } //1 deadlynose
		$a_01_1 = {63 7a 30 30 62 65 6b 27 73 20 53 69 6d 70 6c 65 20 42 61 63 6b 64 6f 6f 72 } //1 cz00bek's Simple Backdoor
		$a_01_2 = {55 73 65 3a 20 25 73 20 3c 70 6f 72 74 3e } //1 Use: %s <port>
		$a_01_3 = {53 70 61 77 6e 69 6e 67 20 73 68 65 6c 6c 2e 2e 2e } //1 Spawning shell...
		$a_01_4 = {73 62 61 63 6b 2e 63 } //1 sback.c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}