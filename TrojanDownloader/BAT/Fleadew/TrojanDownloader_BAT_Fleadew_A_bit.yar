
rule TrojanDownloader_BAT_Fleadew_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Fleadew.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 2e 00 6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 [0-40] 2e 00 6a 00 70 00 67 00 } //10
		$a_01_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 20 00 2f 00 74 00 6e 00 20 00 53 00 69 00 64 00 65 00 62 00 61 00 72 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 2f 00 74 00 72 00 } //1 schtasks /create /sc minute /mo 1 /tn SidebarUpdate /tr
		$a_01_2 = {3a 00 5a 00 6f 00 6e 00 65 00 2e 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 } //1 :Zone.Identifier
		$a_01_3 = {53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 69 00 65 00 44 00 63 00 6f 00 6d 00 4c 00 61 00 75 00 6e 00 63 00 68 00 } //1 SandboxieDcomLaunch
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c } //1 Software\Microsoft\Windows\CurrentVersion\Policies\System\
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}