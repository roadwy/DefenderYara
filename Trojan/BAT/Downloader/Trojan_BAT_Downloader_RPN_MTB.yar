
rule Trojan_BAT_Downloader_RPN_MTB{
	meta:
		description = "Trojan:BAT/Downloader.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-80] 2e 00 65 00 78 00 65 00 } //1
		$a_01_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 schtasks /create
		$a_01_2 = {6e 00 65 00 74 00 73 00 68 00 20 00 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 72 00 75 00 6c 00 65 00 } //1 netsh advfirewall firewall delete rule
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_4 = {44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 } //1 DelegateExecute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}