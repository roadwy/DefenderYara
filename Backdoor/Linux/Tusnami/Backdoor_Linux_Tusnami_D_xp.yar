
rule Backdoor_Linux_Tusnami_D_xp{
	meta:
		description = "Backdoor:Linux/Tusnami.D!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 44 50 5f 41 54 54 41 43 4b 5f 56 45 43 54 4f 52 } //01 00  UDP_ATTACK_VECTOR
		$a_00_1 = {53 59 4e 5f 41 54 54 41 43 4b 5f 56 45 43 54 4f 52 } //01 00  SYN_ATTACK_VECTOR
		$a_00_2 = {41 43 4b 5f 41 54 54 41 43 4b 5f 56 45 43 54 4f 52 } //01 00  ACK_ATTACK_VECTOR
		$a_00_3 = {58 4d 53 5f 41 54 54 41 43 4b 5f 56 45 43 54 4f 52 } //01 00  XMS_ATTACK_VECTOR
		$a_00_4 = {61 74 74 61 63 6b 20 68 61 73 20 62 65 65 6e 20 73 74 61 72 74 65 64 } //01 00  attack has been started
		$a_00_5 = {62 6f 74 6e 65 74 } //01 00  botnet
		$a_00_6 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00  npxXoudifFeEgGaACScs
		$a_00_7 = {67 65 74 73 70 6f 6f 66 } //01 00  getspoof
		$a_00_8 = {49 52 43 20 42 4f 54 4e 45 54 20 43 4f 4d 4d 41 4e 44 } //01 00  IRC BOTNET COMMAND
		$a_00_9 = {66 6c 6f 6f 64 20 3c 68 6f 73 74 3e 20 3c 64 70 6f 72 74 3e 20 3c 73 65 63 6f 6e 64 73 3e } //01 00  flood <host> <dport> <seconds>
		$a_00_10 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //00 00  killer_kill_by_port
	condition:
		any of ($a_*)
 
}