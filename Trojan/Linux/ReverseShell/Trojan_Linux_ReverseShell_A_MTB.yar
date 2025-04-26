
rule Trojan_Linux_ReverseShell_A_MTB{
	meta:
		description = "Trojan:Linux/ReverseShell.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 54 24 20 48 8b 4a f8 48 89 8b 48 03 00 00 48 89 93 40 03 00 00 4c 3b b3 c0 00 00 00 75 07 48 8b 13 48 8b 62 38 48 83 ec 10 48 83 e4 f0 bf 01 00 00 00 48 8d 34 24 48 8b 05 bd b2 57 00 48 83 f8 00 74 3e ff d0 48 8b 04 24 48 8b 54 24 08 4c 89 e4 48 8b 4c 24 08 48 89 8b 40 03 00 00 48 8b 0c 24 48 89 8b 48 03 00 00 } //1
		$a_01_1 = {48 83 ec 18 48 89 6c 24 10 48 8d 6c 24 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 ac d2 53 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 8b 6c 24 10 48 83 c4 18 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}