
rule Trojan_BAT_SmallDownloader_EXP_MTB{
	meta:
		description = "Trojan:BAT/SmallDownloader.EXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 78 7a 2e 38 64 61 73 68 69 2e 63 6f 6d 2f } //1 http://xz.8dashi.com/
		$a_81_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 62 61 69 74 75 73 68 6f 77 } //1 CurrentVersion\Uninstall\baitushow
		$a_81_2 = {63 72 65 61 74 69 6e 67 20 73 6f 63 6b 65 74 } //1 creating socket
		$a_81_3 = {64 6f 77 6e 6c 6f 61 64 } //1 download
		$a_81_4 = {43 6f 6e 6e 65 63 74 69 6e 67 } //1 Connecting
		$a_81_5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4e 53 49 53 44 4c 2f 31 2e 32 20 28 4d 6f 7a 69 6c 6c 61 29 } //1 User-Agent: NSISDL/1.2 (Mozilla)
		$a_81_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_81_7 = {48 6f 73 74 3a 20 78 7a 2e 38 64 61 73 68 69 2e 63 6f 6d } //1 Host: xz.8dashi.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}