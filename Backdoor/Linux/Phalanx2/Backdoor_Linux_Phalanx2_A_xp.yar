
rule Backdoor_Linux_Phalanx2_A_xp{
	meta:
		description = "Backdoor:Linux/Phalanx2.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 64 65 76 2f 73 68 6d 2f 25 73 2e 69 6e 6a 65 63 74 65 64 } //1 /dev/shm/%s.injected
		$a_00_1 = {73 65 74 65 6e 66 6f 72 63 65 20 30 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //1 setenforce 0 2>/dev/null
		$a_00_2 = {74 63 70 34 5f 73 65 71 5f 73 68 6f 77 2e 2e } //1 tcp4_seq_show..
		$a_00_3 = {3a 4f 20 30 78 25 6c 78 20 73 65 65 6d 73 20 66 75 63 6b 65 6e 20 6c 61 72 67 65 } //1 :O 0x%lx seems fucken large
		$a_00_4 = {74 12 b8 00 00 00 00 85 c0 74 09 c7 04 24 28 00 0d 08 ff d0 } //1
		$a_00_5 = {8b 00 0f b6 00 3c 64 75 0e c7 04 24 ac 0d 0b 08 e8 06 91 00 00 eb 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}