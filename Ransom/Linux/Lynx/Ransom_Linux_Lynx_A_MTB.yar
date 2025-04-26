
rule Ransom_Linux_Lynx_A_MTB{
	meta:
		description = "Ransom:Linux/Lynx.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 41 4e 53 4f 4d 57 41 52 45 5f 4e 4f 54 45 2e 52 45 41 44 4d 45 } //1 RANSOMWARE_NOTE.README
		$a_00_1 = {4c 59 4e 58 5f 52 41 4e 53 4f 4d 57 41 52 45 } //1 LYNX_RANSOMWARE
		$a_00_2 = {2e 6c 79 6e 78 } //1 .lynx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}