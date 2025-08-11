
rule Trojan_Win32_Stealga_DA_MTB{
	meta:
		description = "Trojan:Win32/Stealga.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 72 61 74 5c 63 6c 69 65 6e 74 5c 73 74 65 61 6c 65 72 } //10 \rat\client\stealer
		$a_81_1 = {41 56 49 42 72 6f 77 73 65 72 42 61 73 65 40 73 74 65 61 6c 65 72 } //1 AVIBrowserBase@stealer
		$a_81_2 = {41 56 43 68 72 6f 6d 65 42 72 6f 77 73 65 72 40 73 74 65 61 6c 65 72 } //1 AVChromeBrowser@stealer
		$a_81_3 = {41 56 45 64 67 65 42 72 6f 77 73 65 72 40 73 74 65 61 6c 65 72 } //1 AVEdgeBrowser@stealer
		$a_81_4 = {41 56 46 69 72 65 66 6f 78 42 72 6f 77 73 65 72 40 73 74 65 61 6c 65 72 } //1 AVFirefoxBrowser@stealer
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}
rule Trojan_Win32_Stealga_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Stealga.DA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 49 00 6e 00 66 00 6f 00 } //1 System Info
		$a_00_1 = {77 00 6d 00 69 00 63 00 20 00 6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 64 00 69 00 73 00 6b 00 } //1 wmic logicaldisk
		$a_00_2 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 20 00 55 00 73 00 65 00 72 00 20 00 49 00 6e 00 66 00 6f 00 } //1 Administrator User Info
		$a_00_3 = {6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00 20 00 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 } //1 net user administrator
		$a_00_4 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 20 00 2f 00 73 00 76 00 63 00 } //1 tasklist /svc
		$a_00_5 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 61 00 6c 00 6c 00 } //1 ipconfig/all
		$a_00_6 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 2d 00 61 00 6e 00 6f 00 } //1 netstat -ano
		$a_00_7 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 73 00 68 00 6f 00 77 00 } //1 netsh firewall show
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}