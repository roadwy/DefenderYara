
rule Backdoor_Win32_Frintorc_A_dll{
	meta:
		description = "Backdoor:Win32/Frintorc.A!dll,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_01_0 = {31 2e 33 2e 36 2e 31 2e 35 2e 35 2e 37 2e 33 2e 32 } //1 1.3.6.1.5.5.7.3.2
		$a_01_1 = {25 73 3a 25 64 2f 61 73 70 78 61 62 63 64 65 66 67 2e 61 73 70 3f } //1 %s:%d/aspxabcdefg.asp?
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 77 65 62 63 6c 69 65 6e 74 } //1 User-Agent: webclient
		$a_01_3 = {49 4d 4a 50 4d 49 47 } //1 IMJPMIG
		$a_01_4 = {5c 75 73 65 72 2e 69 6e 69 } //1 \user.ini
		$a_01_5 = {74 69 67 65 72 77 6f 6f 64 2e 76 69 63 70 2e 6e 65 74 } //2 tigerwood.vicp.net
		$a_01_6 = {6f 74 6e 61 2e 76 69 63 70 2e 6e 65 74 } //2 otna.vicp.net
		$a_01_7 = {7a 00 69 00 70 00 64 00 67 00 2e 00 64 00 6c 00 6c 00 } //2 zipdg.dll
		$a_01_8 = {73 00 65 00 63 00 75 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //2 secur32.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=11
 
}