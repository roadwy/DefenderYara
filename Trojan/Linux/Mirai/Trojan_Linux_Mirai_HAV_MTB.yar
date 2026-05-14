
rule Trojan_Linux_Mirai_HAV_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {76 71 4d 57 50 41 47 02 67 4c 45 4b 4c 47 02 73 57 47 50 5b 22 00 00 00 51 4a 47 4e 4e 22 00 00 47 4c 43 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}