
rule Trojan_Linux_Sedexp_A_MTB{
	meta:
		description = "Trojan:Linux/Sedexp.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 57 49 89 f7 48 8d 35 74 4f 02 00 41 56 41 55 41 54 55 89 fd 53 48 83 ec 28 48 89 54 24 08 e8 ?? ?? ?? ?? 48 85 c0 0f ?? ?? ?? ?? ?? 49 89 c5 31 db 45 31 f6 31 ed } //1
		$a_03_1 = {31 f6 4c 89 ef e8 ?? ?? ?? ?? 85 c0 74 ?? 48 8d 35 77 3f 02 00 4c 89 ef e8 ?? ?? ?? ?? 48 89 c5 48 85 c0 0f ?? ?? ?? ?? ?? 48 89 c7 48 8d 0d ae 3f 02 00 4c 89 e2 31 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}