
rule Trojan_BAT_Downloader_BI_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 39 31 2e 32 34 33 2e 34 34 2e 32 32 2f 50 4c 2d 34 75 79 2e 62 69 6e } //5 http://91.243.44.22/PL-4uy.bin
		$a_81_1 = {68 74 74 70 3a 2f 2f 39 31 2e 32 34 33 2e 34 34 2e 32 31 2f 67 72 6f 6d 2e 62 69 6e } //5 http://91.243.44.21/grom.bin
		$a_81_2 = {70 69 6e 67 20 62 69 6e 67 2e 63 6f 6d } //1 ping bing.com
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}