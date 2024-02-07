
rule Trojan_Linux_TeamSpeakBot_AA{
	meta:
		description = "Trojan:Linux/TeamSpeakBot.AA,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 68 6d 6f 64 20 2b 78 } //02 00  chmod +x
		$a_00_1 = {42 34 63 6b 64 6f 6f 72 2d 6f 77 6e 65 64 2d 79 6f 75 2d 70 79 74 68 6f 6e 2d 72 65 71 75 65 73 74 73 } //02 00  B4ckdoor-owned-you-python-requests
		$a_00_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 } //02 00  User-Agent: Hello, World
		$a_00_3 = {50 4f 53 54 20 2f 48 4e 41 50 31 2f } //00 00  POST /HNAP1/
	condition:
		any of ($a_*)
 
}