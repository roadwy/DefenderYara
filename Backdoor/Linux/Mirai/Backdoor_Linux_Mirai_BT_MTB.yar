
rule Backdoor_Linux_Mirai_BT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {89 45 d8 8d 04 d5 1e 00 00 00 83 e0 f0 29 c4 31 c0 8d 74 24 0f 83 e6 f0 } //01 00 
		$a_00_1 = {31 c0 89 45 08 f0 83 0c 24 00 8b 44 24 10 05 e4 d0 04 08 8b 40 08 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}