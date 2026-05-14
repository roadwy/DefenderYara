
rule Trojan_Linux_Mirai_HAW_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 41 45 50 4e 22 00 00 00 47 41 4a 4d 22 00 00 00 4f 4d 55 4c 56 22 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}