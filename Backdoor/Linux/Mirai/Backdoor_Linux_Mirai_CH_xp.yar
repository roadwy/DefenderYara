
rule Backdoor_Linux_Mirai_CH_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CH!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {01 7f 84 e3 78 38 a0 00 18 38 c0 00 01 7c 7b 1b 78 7f a3 eb 78 48 00 21 29 7f 84 e3 78 38 a0 00 07 38 c0 } //1
		$a_00_1 = {4a 14 7c 09 03 a6 4e 80 04 20 81 21 51 44 3a 41 00 08 3a c1 01 2c 2e 09 00 00 38 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}