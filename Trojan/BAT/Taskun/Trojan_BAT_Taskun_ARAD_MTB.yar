
rule Trojan_BAT_Taskun_ARAD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 05 2b 2d 07 11 04 11 05 6f 2a 00 00 0a 13 08 07 11 04 11 05 6f 2a 00 00 0a 13 09 11 09 28 2b 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 2c 00 00 0a 32 c9 08 17 58 0c 11 04 17 58 13 04 11 04 07 6f 2d 00 00 0a 32 b0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Taskun_ARAD_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 3a 01 00 5d 13 09 11 08 20 00 3a 01 00 5d 13 0a 07 11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 09 11 0e 11 0b 59 11 07 5d d2 9c 00 11 06 17 58 13 06 11 06 20 00 3a 01 00 fe 04 13 0f 11 0f 2d 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}