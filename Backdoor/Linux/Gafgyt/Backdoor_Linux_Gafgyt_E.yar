
rule Backdoor_Linux_Gafgyt_E{
	meta:
		description = "Backdoor:Linux/Gafgyt.E,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {6b 65 6b 73 65 63 2e 77 61 73 2e 68 65 72 65 } //keksec.was.here  1
		$a_80_1 = {79 6f 75 20 68 61 76 65 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 } //you have been infected by  1
		$a_80_2 = {6b 6e 6f 77 6e 42 6f 74 73 } //knownBots  1
		$a_80_3 = {2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 } ///x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}
rule Backdoor_Linux_Gafgyt_E_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.E,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_00_0 = {31 38 35 2e 32 31 36 2e 32 31 33 2e 31 33 37 } //2 185.216.213.137
		$a_00_1 = {31 39 33 2e 31 34 32 2e 35 38 2e 31 37 31 } //2 193.142.58.171
		$a_00_2 = {34 35 28 34 33 32 28 34 37 33 28 37 36 34 } //1 45(432(473(764
		$a_00_3 = {39 31 2e 32 30 36 2e 39 32 2e 32 30 38 } //2 91.206.92.208
		$a_00_4 = {62 6f 74 6e 65 74 } //1 botnet
		$a_00_5 = {62 6f 74 6b 69 6c 6c } //1 botkill
		$a_00_6 = {24 55 49 43 49 44 45 42 4f 59 24 } //2 $UICIDEBOY$
		$a_00_7 = {50 49 4e 47 } //1 PING
		$a_00_8 = {50 4f 4e 47 } //1 PONG
		$a_00_9 = {42 30 54 4b 31 6c 6c } //1 B0TK1ll
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=4
 
}