
rule Backdoor_Linux_Mirai_BV_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BV!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 44 24 34 89 44 24 0c 0f b6 44 24 12 89 44 24 08 8b 44 24 2c 89 44 24 04 0f b6 44 24 13 89 04 24 } //01 00 
		$a_00_1 = {31 c0 89 44 24 34 8b 44 24 40 85 c0 74 51 0f b6 1f 84 db 88 5c 24 33 0f 85 ae 00 00 00 31 c0 89 44 24 3c } //00 00 
	condition:
		any of ($a_*)
 
}