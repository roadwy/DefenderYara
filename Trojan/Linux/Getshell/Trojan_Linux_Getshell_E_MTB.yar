
rule Trojan_Linux_Getshell_E_MTB{
	meta:
		description = "Trojan:Linux/Getshell.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 30 48 89 7d d8 89 f0 66 89 45 d4 ba 00 00 00 00 be 01 00 00 00 bf 02 00 00 00 e8 ?? ?? ?? ?? 89 45 f4 83 7d f4 00 0f ?? ?? ?? ?? ?? 48 8b 45 d8 48 89 c7 } //1
		$a_03_1 = {48 89 45 f8 48 83 7d f8 00 0f ?? ?? ?? ?? ?? 48 8d 45 e0 be 10 00 00 00 48 89 c7 e8 ?? ?? ?? ?? 66 c7 45 e0 02 00 48 8b 45 f8 8b 40 14 48 63 d0 48 8b 45 f8 48 8b 40 18 48 8b 00 48 8d 4d e0 48 83 c1 04 48 89 ce 48 89 c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}