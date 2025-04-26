
rule Backdoor_Linux_Gafgyt_BE_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 64 61 62 6f 74 } //2 killdabot
		$a_01_1 = {62 6f 74 6b 69 6c 6c } //2 botkill
		$a_01_2 = {62 6f 74 20 2d 75 64 70 } //1 bot -udp
		$a_01_3 = {73 63 61 6e 6e 65 72 } //1 scanner
		$a_01_4 = {62 6f 74 20 2d 74 63 70 } //1 bot -tcp
		$a_01_5 = {4b 69 6c 6c 69 6e 67 20 70 69 64 } //1 Killing pid
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Backdoor_Linux_Gafgyt_BE_xp_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.BE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 66 25 32 30 63 75 72 6c 2e 73 68 25 33 42 } //1 rf%20curl.sh%3B
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_2 = {4d 75 6c 74 69 68 6f 70 20 61 74 74 65 6d 70 74 65 64 } //1 Multihop attempted
		$a_00_3 = {41 63 69 64 20 6d 61 6c 77 61 72 65 } //1 Acid malware
		$a_00_4 = {77 67 65 74 2e 73 68 25 33 42 63 68 6d 6f 64 25 32 30 25 32 42 78 25 32 30 77 67 65 74 2e 73 68 } //1 wget.sh%3Bchmod%20%2Bx%20wget.sh
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}