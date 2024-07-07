
rule Backdoor_Linux_Tsunami_H_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 6f 74 20 2b 75 64 70 } //1 bot +udp
		$a_01_1 = {62 6f 74 20 2b 73 75 64 70 } //1 bot +sudp
		$a_01_2 = {4e 54 50 20 66 6c 6f 6f 64 } //1 NTP flood
		$a_01_3 = {54 43 50 20 66 6c 6f 6f 64 } //1 TCP flood
		$a_00_4 = {6b 69 6c 6c 61 6c 6c 20 2d 39 } //1 killall -9
		$a_00_5 = {2b 6b 69 6c 6c 73 65 63 } //1 +killsec
		$a_01_6 = {4a 4f 4f 4d 4c 41 20 61 74 74 61 63 6b } //1 JOOMLA attack
		$a_01_7 = {53 54 44 20 61 74 74 61 63 6b } //1 STD attack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}