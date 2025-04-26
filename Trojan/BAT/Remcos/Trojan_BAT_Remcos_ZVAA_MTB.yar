
rule Trojan_BAT_Remcos_ZVAA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 1f fd 5f 09 fe 01 13 04 11 04 2c 37 00 03 19 8d ?? 00 00 01 25 16 } //3
		$a_03_1 = {01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 19 8d ?? 00 00 01 25 17 17 9e 25 18 18 9e 13 07 16 13 08 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}