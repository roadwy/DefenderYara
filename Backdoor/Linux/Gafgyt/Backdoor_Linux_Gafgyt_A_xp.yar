
rule Backdoor_Linux_Gafgyt_A_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 42 6f 74 } //1 mBot
		$a_00_1 = {6b 69 6c 6c 61 74 74 6b } //1 killattk
		$a_00_2 = {75 64 70 66 6c 6f 6f 64 } //1 udpflood
		$a_00_3 = {43 32 2d 46 6c 6f 6f 64 20 4f 6e 20 25 73 3a 25 64 20 46 69 6e 69 73 68 65 64 } //1 C2-Flood On %s:%d Finished
		$a_00_4 = {4b 69 6c 6c 65 64 20 25 64 20 41 74 74 61 63 6b 73 } //1 Killed %d Attacks
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}