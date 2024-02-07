
rule Backdoor_Linux_Gafgyt_cf_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.cf!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 4b 49 4c 4c 46 4c 4f 4f 44 53 } //01 00  .KILLFLOODS
		$a_00_1 = {2e 4b 49 4c 4c 50 49 44 } //01 00  .KILLPID
		$a_00_2 = {73 74 6f 70 5f 61 74 74 61 63 6b } //01 00  stop_attack
		$a_00_3 = {74 63 70 5f 61 74 74 61 63 6b } //01 00  tcp_attack
		$a_00_4 = {75 64 70 5f 61 74 74 61 63 6b } //01 00  udp_attack
		$a_00_5 = {73 74 64 5f 61 74 74 61 63 6b } //01 00  std_attack
		$a_00_6 = {78 6d 61 73 5f 61 74 74 61 63 6b } //01 00  xmas_attack
		$a_00_7 = {76 73 65 5f 61 74 74 61 63 6b } //01 00  vse_attack
		$a_00_8 = {6b 69 6c 6c 65 72 5f 73 74 61 72 74 } //01 00  killer_start
		$a_00_9 = {6b 69 6c 6c 5f 6d 61 6c 77 61 72 65 } //01 00  kill_malware
		$a_00_10 = {72 61 6e 64 5f 63 6d 77 63 } //00 00  rand_cmwc
	condition:
		any of ($a_*)
 
}