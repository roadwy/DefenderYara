
rule HackTool_Linux_Dirb_A{
	meta:
		description = "HackTool:Linux/Dirb.A,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {42 79 20 54 68 65 20 44 61 72 6b 20 52 61 76 65 72 } //02 00  By The Dark Raver
		$a_00_1 = {53 70 65 63 69 66 79 20 79 6f 75 72 20 63 75 73 74 6f 6d 20 55 53 45 52 5f 41 47 45 4e 54 2e } //02 00  Specify your custom USER_AGENT.
		$a_00_2 = {2f 75 73 72 2f 73 68 61 72 65 2f 64 69 72 62 2f 77 6f 72 64 6c 69 73 74 73 2f 76 75 6c 6e 73 2f } //02 00  /usr/share/dirb/wordlists/vulns/
		$a_00_3 = {72 65 73 75 6d 65 2f 64 69 72 6c 69 73 74 2e 64 75 6d 70 } //02 00  resume/dirlist.dump
		$a_00_4 = {72 65 73 75 6d 65 2f 77 6f 72 64 6c 69 73 74 2e 64 75 6d 70 } //02 00  resume/wordlist.dump
		$a_00_5 = {70 72 6f 78 79 5f 75 73 65 72 6e 61 6d 65 3a 70 72 6f 78 79 5f 70 61 73 73 77 6f 72 64 } //00 00  proxy_username:proxy_password
	condition:
		any of ($a_*)
 
}