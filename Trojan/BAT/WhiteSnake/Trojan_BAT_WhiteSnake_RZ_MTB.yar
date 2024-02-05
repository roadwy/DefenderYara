
rule Trojan_BAT_WhiteSnake_RZ_MTB{
	meta:
		description = "Trojan:BAT/WhiteSnake.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 08 03 11 08 03 8e 69 5d 91 9e 00 11 08 17 58 13 08 11 08 20 00 01 00 00 fe 04 13 09 11 09 3a da ff ff ff } //01 00 
		$a_01_1 = {09 06 08 94 58 07 08 94 58 20 00 01 00 00 5d 0d 06 08 94 13 0a 06 08 06 09 94 9e 06 09 11 0a 9e 00 08 17 58 0c 08 20 00 01 00 00 fe 04 13 0b 11 0b 3a c9 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}