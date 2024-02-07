
rule Trojan_BAT_Downloader_RPV_MTB{
	meta:
		description = "Trojan:BAT/Downloader.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {37 00 37 00 37 00 2e 00 65 00 78 00 65 00 } //01 00  777.exe
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00  Invoke
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_5 = {62 75 69 6c 64 65 72 2e 70 70 2e 72 75 } //00 00  builder.pp.ru
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Downloader_RPV_MTB_2{
	meta:
		description = "Trojan:BAT/Downloader.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 65 00 78 00 74 00 62 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 72 00 61 00 77 00 } //01 00  textbin.net/raw
		$a_01_1 = {77 00 74 00 66 00 69 00 73 00 6d 00 79 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 65 00 78 00 74 00 } //01 00  wtfismyip.com/text
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {76 00 6d 00 77 00 61 00 72 00 65 00 } //01 00  vmware
		$a_01_4 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 } //01 00  VirtualBox
		$a_01_5 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  passwords.txt
		$a_01_6 = {75 00 70 00 64 00 61 00 74 00 65 00 72 00 72 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  updaterrr.exe
	condition:
		any of ($a_*)
 
}