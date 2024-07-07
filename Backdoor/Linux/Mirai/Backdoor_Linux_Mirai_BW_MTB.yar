
rule Backdoor_Linux_Mirai_BW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 34 24 48 98 66 83 7c 24 14 ff 48 8b 1c c6 4c 8d 63 14 75 09 e8 90 02 05 66 89 43 04 be 14 00 00 00 48 89 df 66 c7 43 0a 00 00 e8 90 02 05 48 63 8c 24 4c 01 00 00 66 89 43 0a 48 89 df 66 41 c7 44 24 10 00 00 48 c1 e1 04 49 8d 74 0d 00 8b 46 04 8d 50 01 66 c1 c8 08 0f b7 c0 89 56 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}