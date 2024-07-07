
rule Backdoor_Linux_Mirai_YA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.YA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f 00 00 20 48 54 54 50 2f 31 2e 31 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 00 0d 0a 48 6f 73 74 3a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}