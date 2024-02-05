
rule Trojan_BAT_SpySnake_MJ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MJ_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 d0 90 01 01 00 00 01 28 90 01 03 0a 90 0a 35 00 d0 12 00 00 01 28 90 01 03 0a 72 90 01 01 00 00 70 72 90 01 01 00 00 70 72 90 01 01 00 00 70 28 90 01 04 17 8d 90 02 12 a2 28 90 01 03 0a 73 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 25 16 72 90 01 01 00 00 70 a2 6f 90 01 03 0a 74 90 01 01 00 00 1b 90 00 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 } //01 00 
		$a_01_3 = {52 65 76 65 72 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}