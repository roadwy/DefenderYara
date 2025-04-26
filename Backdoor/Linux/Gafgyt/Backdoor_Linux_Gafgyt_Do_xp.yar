
rule Backdoor_Linux_Gafgyt_Do_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.Do!xp,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 55 44 50 46 4c 4f 4f 44 } //1 sendUDPFLOOD
		$a_03_1 = {63 64 20 2f 74 6d 70 3b 20 72 6d 20 2d 72 66 20 2a 3b 20 77 67 65 74 20 2d 71 20 68 74 74 70 3a 2f 2f [0-12] 2f 63 6f 63 6b 73 2e 73 68 3b 20 63 68 6d 6f 64 20 2b 78 20 63 6f 63 6b 73 2e 73 68 3b 20 73 68 20 63 6f 63 6b 73 2e 73 68 3b 20 72 6d 20 2d 72 66 20 2a } //1
		$a_00_2 = {47 45 54 20 67 74 6f 70 2e 73 68 } //1 GET gtop.sh
		$a_00_3 = {50 4f 4e 49 45 53 20 43 52 41 43 4b 45 44 } //1 PONIES CRACKED
		$a_00_4 = {49 4e 46 45 43 54 45 44 20 90 02 01 32 7c 32 33 } //1
		$a_00_5 = {4b 49 4c 4c 41 54 54 4b } //1 KILLATTK
		$a_00_6 = {53 54 44 46 4c 4f 4f 44 } //1 STDFLOOD
		$a_00_7 = {4b 69 6c 6c 65 64 20 25 64 2c 20 50 6f 6e 69 65 73 } //1 Killed %d, Ponies
		$a_00_8 = {55 44 50 46 4c 4f 4f 44 } //1 UDPFLOOD
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=8
 
}