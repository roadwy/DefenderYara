
rule PWS_Win32_OnLineGames_CSO{
	meta:
		description = "PWS:Win32/OnLineGames.CSO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {49 50 45 6e 61 62 6c 65 52 6f 75 74 65 72 } //1 IPEnableRouter
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 63 70 69 70 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
		$a_01_2 = {47 45 54 00 48 54 54 50 2f 31 2e 30 } //1 䕇T呈偔ㄯ〮
		$a_01_3 = {61 63 74 69 6f 6e 3d 35 26 6b 65 79 69 64 3d 25 73 } //1 action=5&keyid=%s
		$a_01_4 = {61 63 74 69 6f 6e 3d 34 26 66 6f 6f 6c 69 70 3d 25 73 } //1 action=4&foolip=%s
		$a_01_5 = {61 63 74 69 6f 6e 3d 33 26 66 6f 6f 6c 69 70 3d 25 73 26 61 73 64 66 3d 25 73 } //1 action=3&foolip=%s&asdf=%s
		$a_01_6 = {61 63 74 69 6f 6e 3d 32 26 66 6f 6f 6c 69 70 3d 25 73 } //1 action=2&foolip=%s
		$a_01_7 = {61 63 74 69 6f 6e 3d 31 } //1 action=1
		$a_01_8 = {61 63 74 69 6f 6e 3d 30 26 6b 65 79 69 64 3d 25 73 26 66 6f 6f 6c 69 70 3d 25 73 } //1 action=0&keyid=%s&foolip=%s
		$a_01_9 = {50 4f 50 54 41 4e 47 } //1 POPTANG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}