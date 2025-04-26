
rule Backdoor_Linux_Mirai_BO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {89 e5 0f b6 55 08 0f b6 45 0c 0f b6 4d 10 c1 e2 18 c1 e0 10 09 c2 0f b6 45 14 c1 e1 08 5d 09 c2 09 d1 89 ca 89 c8 81 e2 00 ff 00 00 c1 e2 08 c1 e0 18 09 d0 89 ca 81 e1 00 00 ff 00 c1 ea 18 c1 e9 08 09 ca 09 d0 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}