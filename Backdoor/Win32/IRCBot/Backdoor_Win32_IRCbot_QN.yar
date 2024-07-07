
rule Backdoor_Win32_IRCbot_QN{
	meta:
		description = "Backdoor:Win32/IRCbot.QN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {5c 77 69 6e 61 70 69 2e 65 78 65 90 02 0f 68 74 74 70 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 90 02 05 2f 77 69 6e 61 70 69 2e 74 78 74 90 00 } //2
		$a_00_1 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \FileZilla\recentservers.xml
		$a_00_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 76 62 63 2e 65 78 65 } //1 taskkill /F /IM vbc.exe
		$a_00_3 = {55 53 45 52 20 48 34 58 30 52 2d 42 30 54 20 22 } //1 USER H4X0R-B0T "
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}