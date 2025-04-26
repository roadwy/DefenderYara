
rule Trojan_Win32_KillAV_A_MTB{
	meta:
		description = "Trojan:Win32/KillAV.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6d 73 69 6e 66 6f 2e 65 78 65 } //1 taskkill /f /im msinfo.exe
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 taskkill /f /im rundll32.exe
		$a_01_2 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 45 73 65 74 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%Eset%'" call uninstall /nointeractive
		$a_01_3 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 25 4b 61 73 70 65 72 73 6b 79 25 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%%Kaspersky%%'" call uninstall /nointeractive
		$a_01_4 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 61 76 61 73 74 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%avast%'" call uninstall /nointeractive
		$a_01_5 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 61 76 70 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%avp%'" call uninstall /nointeractive
		$a_01_6 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 53 65 63 75 72 69 74 79 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%Security%'" call uninstall /nointeractive
		$a_01_7 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 41 6e 74 69 56 69 72 75 73 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%AntiVirus%'" call uninstall /nointeractive
		$a_01_8 = {77 6d 69 63 2e 65 78 65 20 70 72 6f 64 75 63 74 20 77 68 65 72 65 20 22 6e 61 6d 65 20 6c 69 6b 65 20 27 25 4e 6f 72 74 6f 6e 20 53 65 63 75 72 69 74 79 25 27 22 20 63 61 6c 6c 20 75 6e 69 6e 73 74 61 6c 6c 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic.exe product where "name like '%Norton Security%'" call uninstall /nointeractive
		$a_01_9 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 22 74 63 70 20 61 6c 6c 22 20 64 69 72 3d 69 6e } //1 netsh advfirewall firewall delete rule name="tcp all" dir=in
		$a_01_10 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 22 74 63 70 61 6c 6c 22 20 64 69 72 3d 6f 75 74 } //1 netsh advfirewall firewall delete rule name="tcpall" dir=out
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}