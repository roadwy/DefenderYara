
rule Trojan_Linux_Getshell_G_xp{
	meta:
		description = "Trojan:Linux/Getshell.G!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 97 52 c7 04 24 90 01 04 48 89 e6 6a 10 5a 6a 31 58 0f 05 6a 32 58 0f 05 48 31 f6 6a 2b 58 0f 05 48 97 6a 03 5e 48 ff ce 6a 21 58 0f 05 75 f6 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 52 57 48 89 e6 0f 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}