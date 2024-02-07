
rule HackTool_MacOS_SusUrlAccess_A{
	meta:
		description = "HackTool:MacOS/SusUrlAccess.A,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 0b 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 } //01 00  curl
		$a_00_1 = {77 00 67 00 65 00 74 00 } //01 00  wget
		$a_00_2 = {67 00 69 00 74 00 } //0a 00  git
		$a_00_3 = {2e 00 74 00 6f 00 72 00 32 00 77 00 65 00 62 00 } //0a 00  .tor2web
		$a_00_4 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 } //0a 00  .onion
		$a_00_5 = {2e 00 74 00 6f 00 72 00 32 00 73 00 6f 00 63 00 6b 00 73 00 } //0a 00  .tor2socks
		$a_00_6 = {65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 2d 00 64 00 62 00 2e 00 63 00 6f 00 6d 00 } //0a 00  exploit-db.com
		$a_00_7 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 } //0a 00  pastebin.com
		$a_00_8 = {61 00 6e 00 6f 00 6e 00 66 00 69 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 } //00 00  anonfile.com
	condition:
		any of ($a_*)
 
}