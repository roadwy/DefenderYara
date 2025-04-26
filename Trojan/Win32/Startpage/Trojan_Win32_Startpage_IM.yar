
rule Trojan_Win32_Startpage_IM{
	meta:
		description = "Trojan:Win32/Startpage.IM,SIGNATURE_TYPE_PEHSTR,06 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //1 \Microsoft\Internet Explorer\Quick Launch
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {74 6e 3d 6c 65 69 7a 68 65 6e } //1 tn=leizhen
		$a_01_4 = {57 69 6e 64 6f 77 73 20 53 63 72 69 70 74 69 6e 67 20 48 6f 73 74 } //1 Windows Scripting Host
		$a_01_5 = {54 68 65 57 6f 72 6c 64 2e 69 6e 69 } //1 TheWorld.ini
		$a_01_6 = {5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c 43 6f 6d 6d 61 6e 64 } //1 \OpenHomePage\Command
		$a_01_7 = {6d 61 69 6e 00 00 00 00 68 6f 6d 65 70 61 67 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}