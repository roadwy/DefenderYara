
rule Trojan_BAT_Downloader_BB_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 44 6f 76 4c 7a 45 35 4d 79 34 78 4e 7a 67 75 4d 54 59 35 4c 6a 45 34 4e 69 39 30 63 6d 46 6d 5a 69 35 6c 65 47 55 } //01 00  aHR0cDovLzE5My4xNzguMTY5LjE4Ni90cmFmZi5leGU
		$a_81_1 = {5a 6d 6c 70 61 57 6e 51 73 48 4e 6b 63 39 43 77 61 57 6c 79 63 6e 4e 30 4c 6e 52 34 64 41 3d 3d } //01 00  ZmlpaWnQsHNkc9CwaWlycnN0LnR4dA==
		$a_01_2 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {64 65 76 63 76 63 78 78 78 63 64 6f 64 65 } //01 00  devcvcxxxcdode
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}