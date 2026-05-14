
rule Trojan_Win32_Tinukebot_A_AMTB{
	meta:
		description = "Trojan:Win32/Tinukebot.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //1 %s\Microsoft\Edge\User Data
		$a_81_1 = {53 65 6e 64 20 44 61 74 61 20 46 61 69 6c } //2 Send Data Fail
		$a_81_2 = {5c 63 68 72 6f 6d 65 2e 74 78 74 } //1 \chrome.txt
		$a_81_3 = {25 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //1 %s\Google\Chrome\User Data
		$a_81_4 = {5b 63 68 72 6f 6d 65 2e 74 78 74 5d 20 73 63 75 63 65 73 73 66 75 6c } //2 [chrome.txt] scucessful
		$a_01_5 = {62 30 52 30 57 40 57 } //2 b0R0W@W
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2+(#a_01_5  & 1)*2) >=6
 
}