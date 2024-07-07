
rule Backdoor_Linux_Getshell_AB_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.AB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 48 83 ec 30 c7 45 fc 29 23 00 00 ba 00 00 00 00 be 01 00 00 00 bf 02 00 00 00 e8 d4 fe ff ff 89 45 f8 66 c7 45 e0 02 00 8b 45 fc 0f b7 c0 89 c7 e8 6e fe ff ff 66 89 45 e2 48 8d 05 37 0e 00 00 48 89 c7 e8 8b fe ff ff 89 45 e4 48 8d 4d e0 8b 45 f8 ba 10 00 00 00 48 89 ce 89 c7 e8 82 fe ff ff 8b 45 f8 be 00 00 00 00 89 c7 e8 43 fe ff ff 8b 45 f8 be 01 00 00 00 89 c7 e8 34 fe ff ff 8b 45 f8 be 02 00 00 00 89 c7 e8 25 fe ff ff 48 8d 05 ee 0d 00 00 48 89 45 d0 48 c7 45 d8 00 00 00 00 48 8d 45 d0 ba 00 00 00 00 48 89 c6 48 8d 05 cf 0d 00 00 48 89 c7 e8 07 fe ff ff b8 00 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}