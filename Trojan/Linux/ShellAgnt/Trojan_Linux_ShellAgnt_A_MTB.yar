
rule Trojan_Linux_ShellAgnt_A_MTB{
	meta:
		description = "Trojan:Linux/ShellAgnt.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 89 e8 ff d0 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 6a 0a 68 0a 00 02 61 } //01 00 
		$a_00_1 = {68 0a 00 02 61 68 02 00 1a 0a 89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 0a ff 4e 08 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}