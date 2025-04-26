
rule Backdoor_Linux_Gafgyt_cf_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.cf!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0b 00 00 "
		
	strings :
		$a_00_0 = {2e 4b 49 4c 4c 46 4c 4f 4f 44 53 } //1 .KILLFLOODS
		$a_00_1 = {2e 4b 49 4c 4c 50 49 44 } //1 .KILLPID
		$a_00_2 = {73 74 6f 70 5f 61 74 74 61 63 6b } //1 stop_attack
		$a_00_3 = {74 63 70 5f 61 74 74 61 63 6b } //1 tcp_attack
		$a_00_4 = {75 64 70 5f 61 74 74 61 63 6b } //1 udp_attack
		$a_00_5 = {73 74 64 5f 61 74 74 61 63 6b } //1 std_attack
		$a_00_6 = {78 6d 61 73 5f 61 74 74 61 63 6b } //1 xmas_attack
		$a_00_7 = {76 73 65 5f 61 74 74 61 63 6b } //1 vse_attack
		$a_00_8 = {6b 69 6c 6c 65 72 5f 73 74 61 72 74 } //1 killer_start
		$a_00_9 = {6b 69 6c 6c 5f 6d 61 6c 77 61 72 65 } //1 kill_malware
		$a_00_10 = {72 61 6e 64 5f 63 6d 77 63 } //1 rand_cmwc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=3
 
}