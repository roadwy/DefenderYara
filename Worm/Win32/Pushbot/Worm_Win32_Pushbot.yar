
rule Worm_Win32_Pushbot{
	meta:
		description = "Worm:Win32/Pushbot,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 12 00 00 "
		
	strings :
		$a_00_0 = {6d 73 6e 2e 73 70 72 65 61 64 } //5 msn.spread
		$a_00_1 = {25 73 20 4b 69 6c 6c 3a 20 3c 25 64 3e 20 74 68 72 65 61 64 73 } //5 %s Kill: <%d> threads
		$a_00_2 = {25 73 20 42 6f 74 20 69 6e 73 74 61 6c 6c 65 64 20 6f 6e 3a 20 25 73 2e } //5 %s Bot installed on: %s.
		$a_00_3 = {25 73 20 53 70 79 3a 20 25 73 21 25 73 40 25 73 20 28 50 4d 3a 20 22 25 73 22 29 } //5 %s Spy: %s!%s@%s (PM: "%s")
		$a_00_4 = {4a 4f 49 4e 20 25 73 } //1 JOIN %s
		$a_00_5 = {50 52 49 56 4d 53 47 20 25 73 } //1 PRIVMSG %s
		$a_00_6 = {64 65 6c 20 22 25 73 22 3e 6e 75 6c } //1 del "%s">nul
		$a_00_7 = {64 65 6c 20 22 25 25 30 22 } //1 del "%%0"
		$a_00_8 = {70 69 6e 67 20 30 2e 30 2e 30 2e 30 3e 6e 75 6c } //1 ping 0.0.0.0>nul
		$a_00_9 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 if exist "%s" goto Repeat
		$a_00_10 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //1 %s\removeMe%i%i%i%i.bat
		$a_00_11 = {73 6f 63 6b 65 74 } //1 socket
		$a_00_12 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e } //1 InternetOpen
		$a_01_13 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_00_14 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //1 InternetConnectA
		$a_00_15 = {6d 73 6e 6d 73 67 73 2e 65 78 65 } //1 msnmsgs.exe
		$a_00_16 = {2a 21 2a 40 62 6f 73 73 2e 67 6f 76 } //1 *!*@boss.gov
		$a_00_17 = {61 72 79 61 6e 2e 6f 70 65 6e 64 6e 73 2e 62 65 } //1 aryan.opendns.be
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_01_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1) >=25
 
}