
rule Backdoor_Linux_Mirai_EP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b 14 24 89 51 10 41 0f b6 44 24 04 49 83 c4 05 66 c7 01 02 00 89 51 04 88 41 14 48 83 c1 18 4c 39 e6 75 db ?? ?? ?? 29 c3 } //1
		$a_01_1 = {48 83 7c 24 18 00 0f 84 e6 fd ff ff 44 0f b6 64 24 17 45 85 e4 7e 1f 48 8b 5c 24 18 31 ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}