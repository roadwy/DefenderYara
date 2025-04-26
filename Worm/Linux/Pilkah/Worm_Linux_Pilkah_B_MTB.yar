
rule Worm_Linux_Pilkah_B_MTB{
	meta:
		description = "Worm:Linux/Pilkah.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 67 73 79 6e 66 6c 6f 6f 64 } //1 ngsynflood
		$a_00_1 = {61 63 6b 66 6c 6f 6f 64 } //1 ackflood
		$a_00_2 = {6e 67 61 63 6b 66 6c 6f 6f 64 } //1 ngackflood
		$a_00_3 = {2f 76 61 72 2f 72 75 6e 2f 2e 6c 69 67 68 74 70 69 64 } //1 /var/run/.lightpid
		$a_00_4 = {4c 69 67 68 74 61 69 64 72 61 } //1 Lightaidra
		$a_00_5 = {67 65 74 5f 73 70 6f 6f 66 65 64 } //1 get_spoofed
		$a_00_6 = {2f 76 61 72 2f 72 75 6e 2f 2e 6c 69 67 68 74 73 63 61 6e } //1 /var/run/.lightscan
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}