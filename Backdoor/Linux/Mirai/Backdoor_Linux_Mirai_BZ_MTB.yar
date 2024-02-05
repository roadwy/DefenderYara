
rule Backdoor_Linux_Mirai_BZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {03 10 a0 e3 11 20 a0 e3 02 00 a0 e3 1a 10 00 eb 01 80 a0 e3 04 c0 a0 e3 00 10 a0 e3 03 20 a0 e3 0b 30 a0 e1 0a 00 84 e7 00 c0 8d e5 0c 40 84 e0 1c 80 8d e5 fe 0f 00 eb 01 00 70 e3 ed ff ff 1a 09 00 a0 e1 09 10 a0 e3 0e 0c 00 eb } //00 00 
	condition:
		any of ($a_*)
 
}