
rule Trojan_Win64_ShellInject_DB_MTB{
	meta:
		description = "Trojan:Win64/ShellInject.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 68 65 6c 6c 63 6f 64 65 4c 6f 61 64 65 72 } //10 ShellcodeLoader
		$a_81_1 = {59 77 41 59 77 41 6f 6e 76 73 67 48 55 62 6e 6f 59 77 41 6f 6e 76 73 67 48 55 62 6e 6e 76 73 67 48 55 62 6e } //10 YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn
		$a_81_2 = {73 6d 61 72 74 73 63 72 65 65 6e } //1 smartscreen
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1) >=21
 
}