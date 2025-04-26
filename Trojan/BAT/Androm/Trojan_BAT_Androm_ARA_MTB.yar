
rule Trojan_BAT_Androm_ARA_MTB{
	meta:
		description = "Trojan:BAT/Androm.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 08 03 8e 69 5d 94 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 00 08 17 59 0c 08 16 fe 04 16 fe 01 13 05 11 05 2d d5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Androm_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Androm.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 11 07 11 06 11 07 91 1b 59 20 00 01 00 00 58 20 ?? ?? ?? ?? 5a 20 00 01 00 00 5d d2 9c 11 06 11 07 8f ?? ?? ?? ?? 25 47 03 09 58 20 00 01 00 00 5d d2 61 d2 52 00 11 07 17 58 13 07 11 07 11 06 8e 69 fe 04 13 08 11 08 2d b3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}