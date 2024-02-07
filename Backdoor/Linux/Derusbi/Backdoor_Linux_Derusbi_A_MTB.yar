
rule Backdoor_Linux_Derusbi_A_MTB{
	meta:
		description = "Backdoor:Linux/Derusbi.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {38 31 62 63 33 66 30 35 65 35 31 33 64 64 30 66 30 33 37 63 62 30 64 38 31 61 66 39 65 64 62 64 } //01 00  81bc3f05e513dd0f037cb0d81af9edbd
		$a_00_1 = {2f 64 65 76 2f 73 68 6d 2f 2e 70 72 6f 66 69 6c 65 5f 6c 6f 67 } //01 00  /dev/shm/.profile_log
		$a_00_2 = {2f 64 65 76 2f 73 68 6d 2f 2e 73 68 6d 66 73 2e 6c 6f 63 6b } //01 00  /dev/shm/.shmfs.lock
		$a_00_3 = {5c 75 40 5c 68 3a 5c 77 20 5c 24 } //01 00  \u@\h:\w \$
		$a_00_4 = {2f 74 6d 70 2f 2e 73 65 63 75 72 65 } //01 00  /tmp/.secure
		$a_00_5 = {89 c1 89 f7 83 c0 01 83 e1 03 c1 e1 03 d3 ef 40 30 3b 48 83 c3 01 39 d0 72 e6 e9 35 ff ff ff } //01 00 
		$a_00_6 = {8b 85 e4 fd ff ff 89 f1 83 c6 01 83 e1 03 c1 e1 03 d3 e8 30 02 83 c2 01 39 f7 77 e4 } //00 00 
		$a_00_7 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}