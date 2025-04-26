
rule Backdoor_Linux_Gafgyt_BK_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {8b 45 e0 c1 e0 02 03 45 e0 01 c0 89 45 e0 8b 45 0c 0f b6 00 0f b6 c0 03 45 e0 83 e8 30 89 45 e0 ff 45 0c 8b 45 0c 0f b6 00 3c 2f 76 0a 8b 45 0c 0f b6 00 3c 39 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}