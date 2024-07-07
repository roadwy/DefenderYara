
rule Trojan_BAT_AgentTesla_D_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.D!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 00 6f 00 67 00 75 00 65 00 6c 00 69 00 6b 00 65 00 2e 00 62 00 69 00 6e 00 } //1 roguelike.bin
		$a_01_1 = {67 65 74 5f 45 6e 63 72 79 70 74 65 64 } //1 get_Encrypted
		$a_01_2 = {4d 61 7a 65 } //1 Maze
		$a_01_3 = {6e 00 65 00 77 00 77 00 6f 00 72 00 6c 00 64 00 6f 00 72 00 64 00 65 00 72 00 } //1 newworldorder
		$a_01_4 = {41 00 63 00 69 00 64 00 20 00 42 00 6c 00 6f 00 62 00 } //1 Acid Blob
		$a_01_5 = {43 00 68 00 61 00 69 00 6e 00 20 00 4d 00 61 00 69 00 6c 00 } //1 Chain Mail
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}