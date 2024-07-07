
rule Backdoor_Win32_IRCbot_MTB{
	meta:
		description = "Backdoor:Win32/IRCbot!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 41 53 53 } //1 PASS
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
		$a_00_2 = {44 65 73 6b 74 6f 70 2e 69 6e 69 } //1 Desktop.ini
		$a_80_3 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //autorun.inf  1
		$a_00_4 = {36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 } //1 645FF040-5081-101B-9F08-00AA002F954E
		$a_00_5 = {55 73 65 41 75 54 4f 50 4c 41 59 3d 31 } //1 UseAuTOPLAY=1
		$a_00_6 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //1 %s\removeMe%i%i%i%i.bat
		$a_00_7 = {70 69 6e 67 20 30 2e 30 2e 30 2e 30 3e 6e 75 6c } //1 ping 0.0.0.0>nul
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}