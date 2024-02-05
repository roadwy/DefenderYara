
rule Backdoor_MacOS_RShell_A_MTB{
	meta:
		description = "Backdoor:MacOS/RShell.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 8b 3d 73 4b 01 00 48 8d 35 21 31 01 00 ba 19 00 00 00 e8 c0 84 ff ff 48 89 c3 48 8b 00 48 8b 70 e8 48 01 de 48 8d 7d c0 e8 f6 e8 00 00 48 8b 35 4d 4b 01 00 48 8d 7d c0 e8 e0 e8 00 00 48 8b 08 48 89 c7 be 0a 00 00 00 ff 51 38 41 89 c5 48 8d 7d c0 e8 8c e9 00 00 41 0f be f5 48 89 df e8 44 e9 00 00 48 89 df } //00 00 
	condition:
		any of ($a_*)
 
}